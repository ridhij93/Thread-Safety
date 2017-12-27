#include "definitions.h"
#include "ThreadLocalData.h"
#include "Lock.h"
#include <mutex>
#include "pinplay.H"
#include "MemoryAddr.h"
#include <string>
#include <vector>
#include <map>
#include <sched.h>
#include <mutex>
#include <semaphore.h>
#include "Dyn.h"

#define window_size 1
#define MAX_PRIORITY 5
#define MID_PRIORITY 4
#define MIN_PRIORITY 2
#define MIN_PRIORITY2 1
PINPLAY_ENGINE pinplay_engine;
KNOB<BOOL> KnobPinPlayLogger(KNOB_MODE_WRITEONCE,
                      "pintool", "log", "0",
                      "Activate the pinplay logger");

KNOB<BOOL> KnobPinPlayReplayer(KNOB_MODE_WRITEONCE,
                      "pintool", "replay", "0",
                      "Activate the pinplay replayer");
int j;int sched_inst=0;
bool insert=false;
Dyn d;
bool waiting=false;
bool picked_races=false;
bool picked_relax=false;
bool first_run=false;
ofstream file;
sem_t sem;
int tid1,tid2,i_count1,i_count2;
string ins1, ins2;
ofstream instruction;
ofstream file_races;
ofstream file_relax;
string ins_l,ins_s;
INS ins_send;
int place=-1;
struct execution_element
{
    THREADID tid;
    int i_count;
    string ins;
    char type;
    ADDRINT addr;
    VectorClock* vc;
};

struct done_element
{
    THREADID tid;
    int i_count;
    string ins;
    char type;
    ADDRINT addr;
    string status = "none";
};

vector<done_element> done;
vector<execution_element> execution_history;
vector<pair<execution_element,execution_element>> data_race;
vector<pair<execution_element,execution_element>> relax_tso;
vector<pair<execution_element,execution_element>> relax_pso;
vector<execution_element> prev;
execution_element store;
execution_element load;
vector<pair<execution_element,execution_element>> table;
vector<execution_element> store_buffer;
map<THREADID, vector<execution_element>> buffers;
map<THREADID, vector<execution_element>> buffers_tso;
map<THREADID,map< string,vector<execution_element>>> buffer_pso;

// Contains knobs to filter out things to instrument
FILTER filter;
int window=0;

vector<Lock*> allLocks;
list<MemoryAddr*> memSet;

int totalThreads = 0;
int totalins = 0;
PIN_LOCK GlobalLock;
TLS_KEY tls_key;
std::mutex mtx;
set<ADDRINT> writeIntersection;

map<THREADID, THREADID> mapOfThreadIDs;

ofstream sharedAccesses;
ofstream races;

template <class T>
inline void PRINT_ELEMENTS (const T& coll, ThreadLocalData *tld, const char* optcstr="")
{
    typename T::const_iterator pos;

    tld->out << optcstr;
    for (pos=coll.begin(); pos!=coll.end(); ++pos) {
        tld->out << *pos << ' ';
    }
    tld->out << std::endl;
}

template <class T>
inline void PRINT_ELEMENTS_OUTPUT (const T& coll, const char* optcstr="")
{
    typename T::const_iterator pos;

    cout << optcstr;
    for (pos=coll.begin(); pos!=coll.end(); ++pos) {
        cout << *pos << ' ';
    }
    cout << std::endl;
}

void updateMemoryClocks(ThreadLocalData* tld, Lock* lock){
    set<ADDRINT>::const_iterator pos;

    for(pos=lock->memReadAccesses.begin(); pos!=lock->memReadAccesses.end(); ++pos){
        list<MemoryAddr*>::const_iterator lookup = 
                find_if(memSet.begin(), memSet.end(), mem_has_addr(*pos));
        if(lookup!=memSet.end()){
            int j;
            int size = (*lookup)->accessingInstructions.size();
            for(j=0; j< size; j++){
                if(((*lookup)->accessingInstructions[j] > lock->lock_inst)
                    && ((*lookup)->accessingInstructions[j] < lock->unlock_inst) 
                    && (tld->threadId==(*lookup)->accessingThread[j])){
                    (*lookup)->accessClocks[j].receiveActionFromSpecialPoint(tld->currentVectorClock, tld->threadId);
                }
            }
        }

    }

    for(pos=lock->memWriteAccesses.begin(); pos!=lock->memWriteAccesses.end(); ++pos){
        list<MemoryAddr*>::const_iterator lookup = 
                find_if(memSet.begin(), memSet.end(), mem_has_addr(*pos));
        if(lookup!=memSet.end()){
            int j;
            int size = (*lookup)->accessingInstructions.size();
            for(j=0; j< size; j++){
                if(((*lookup)->accessingInstructions[j] > lock->lock_inst)
                    && ((*lookup)->accessingInstructions[j] < lock->unlock_inst) 
                    && (tld->threadId==(*lookup)->accessingThread[j])){
                    (*lookup)->accessClocks[j].receiveActionFromSpecialPoint(tld->currentVectorClock, tld->threadId);
                }
            }
        }

    }
    
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v){
	cout << "Thread Start:" << threadid << endl;
    ThreadLocalData* tld = new ThreadLocalData(threadid);
    
     if(threadid == 0){
        PIN_GetLock(&GlobalLock, tld->threadId);
        mapOfThreadIDs[threadid] = PIN_GetTid();
        PIN_ReleaseLock(&GlobalLock);
    
    	stringstream fileName;
    	fileName << "thread" << threadid << ".out";
    	KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", fileName.str(), "specify output file name");
        tld->out.open(KnobOutputFile.Value().c_str());

        stringstream traceName;
        traceName << "thread_trace" << threadid << ".out";
        KNOB<string> KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", traceName.str(), "specify output file name");
        tld->thread_trace.open(KnobTraceFile.Value().c_str());

        stringstream readSet;
        readSet << "readSet" << threadid << ".out";
        ifstream read(readSet.str().c_str());
        string line;
        for (unsigned int i=1; getline(read, line); ++i)
            tld->readSet.insert(atoll(line.c_str()));

        stringstream writeSet;
        writeSet << "writeSet" << threadid << ".out";
        ifstream write(writeSet.str().c_str());
        for (unsigned int i=1; getline(write, line); ++i)
            tld->writeSet.insert(atoll(line.c_str()));

    	PIN_SetThreadData(tls_key, tld, threadid);
    	PIN_GetLock(&GlobalLock, threadid);
    	++totalThreads;
    	PIN_ReleaseLock(&GlobalLock);
    }
    else{
        THREADID parentThreadId = 0;
        PIN_GetLock(&GlobalLock, tld->threadId);
        mapOfThreadIDs[threadid] = PIN_GetTid();
        THREADID parentTid = PIN_GetParentTid();
        if (mapOfThreadIDs.count(parentTid) > 0)
            parentThreadId = mapOfThreadIDs[parentTid];
        PIN_ReleaseLock(&GlobalLock);

        ThreadLocalData* parentTls = getTLS(parentThreadId);

        PIN_GetLock(&parentTls->threadLock, threadid);

        parentTls->currentVectorClock->event();

        tld->currentVectorClock->receiveAction(parentTls->currentVectorClock);
        PIN_ReleaseLock(&parentTls->threadLock);
    
        stringstream fileName;
        fileName << "thread" << threadid << ".out";
        KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", fileName.str(), "specify output file name");
        tld->out.open(KnobOutputFile.Value().c_str());

        stringstream traceName;
        traceName << "thread_trace" << threadid << ".out";
        KNOB<string> KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", traceName.str(), "specify output file name");
        tld->thread_trace.open(KnobTraceFile.Value().c_str());

        stringstream readSet;
        readSet << "readSet" << threadid << ".out";
        ifstream read(readSet.str().c_str());
        string line;
        for (unsigned int i=1; getline(read, line); ++i)
            tld->readSet.insert(atoll(line.c_str()));

        stringstream writeSet;
        writeSet << "writeSet" << threadid << ".out";
        ifstream write(writeSet.str().c_str());
        for (unsigned int i=1; getline(write, line); ++i)
            tld->writeSet.insert(atoll(line.c_str()));

        PIN_SetThreadData(tls_key, tld, threadid);
        PIN_GetLock(&GlobalLock, threadid);
        ++totalThreads;
        PIN_ReleaseLock(&GlobalLock);
    }
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v){
    ThreadLocalData* tld = getTLS(threadid);
    tld->out.close();
    if(threadid!=0){
        THREADID parentThreadId = 0;
        PIN_GetLock(&GlobalLock, tld->threadId);
        mapOfThreadIDs[threadid] = PIN_GetTid();
        THREADID parentTid = PIN_GetParentTid();
        if (mapOfThreadIDs.count(parentTid) > 0)
            parentThreadId = mapOfThreadIDs[parentTid];
        PIN_ReleaseLock(&GlobalLock);

        ThreadLocalData *parentTls = getTLS(parentThreadId);

        parentTls->currentVectorClock->receiveAction(tld->currentVectorClock);
        parentTls->currentVectorClock->event();
    }
    cout << "Thread Finished:" << threadid << endl;
    free(tld);
    PIN_SetThreadData(tls_key, 0, threadid);
}

VOID CheckCMPXCHG(THREADID threadid, INS ins){
    ThreadLocalData* tld = getTLS(threadid);
    if(INS_Opcode(ins)==CMPXCHG){
        tld->isCMPXCHG = 1;
    }
}

VOID CheckEAX(THREADID threadid, ADDRINT value, REG _reg, INS ins){
    PIN_LockClient();
    ThreadLocalData* tld = getTLS(threadid);
    if(REG_FullRegName(_reg)==EAX_REG && value==0){
        tld->isEAXZero = 1;
    }
    if(REG_FullRegName(_reg)==EAX_REG && value==2){
        tld->isEAXTwo = 1;
    }
    PIN_UnlockClient();
}

VOID SetUpMemoryParams(THREADID threadid, ADDRINT effective_address, UINT32 size) {
    ThreadLocalData* tld = getTLS(threadid);
    MemoryWrite *memory = (MemoryWrite *) malloc(sizeof(MemoryWrite));
    memory->effective_address = effective_address;
    memory->size = size;
    tld->memoryOperandsBefore.push(memory);
}

VOID RecordMemoryWriteBeforeINS(THREADID threadid, INS ins) {
    PIN_LockClient();
    ThreadLocalData* tld = getTLS(threadid);
    ADDRINT value = 0;
    size_t res = 0;

    while (!tld->memoryOperandsBefore.empty()) {
        MemoryWrite *memoryWrite = tld->memoryOperandsBefore.front();
        tld->memoryOperandsBefore.pop();
        tld->memoryOperandsAfter.push(memoryWrite);

        res = PIN_SafeCopy(&value, (VOID *) memoryWrite->effective_address, memoryWrite->size);
        if (res == memoryWrite->size) {
        	PIN_GetLock(&GlobalLock, tld->threadId);
              bool found;
            vector<Lock*>::const_iterator lookup = 
                find_if(allLocks.begin(), allLocks.end(), lock_has_addr(memoryWrite->effective_address));
            if(lookup==allLocks.end())
                found = false;
            else
                found = (*lookup)->isLocked;
            PIN_ReleaseLock(&GlobalLock);

            if(value==0 && !found){
                tld->isZeroBefore = 1;
            }
            else if(value==1 && !found){
                tld->isOneBeforeAndUnlocked = 1;
            }

            else if(value==1 && found){
                tld->isOneBeforeAndLocked = 1;
            }
            else if(value==2 && found)
                tld->isTwoBefore = 1;
        }
    }
    PIN_UnlockClient();
}

VOID RecordMemoryWriteAfterINS(THREADID threadid,INS ins) {
    PIN_LockClient();
    ThreadLocalData* tld = getTLS(threadid);
    ADDRINT value = 0;
    size_t res = 0;
    MemoryWrite *lockMemoryWrite = (MemoryWrite *) malloc(sizeof(MemoryWrite));
    while (!tld->memoryOperandsAfter.empty()) {
        MemoryWrite *memoryWrite = tld->memoryOperandsAfter.front();
        tld->memoryOperandsAfter.pop();

        res = PIN_SafeCopy(&value, (VOID *) memoryWrite->effective_address, memoryWrite->size);
        if (res == memoryWrite->size) {
            PIN_GetLock(&GlobalLock, tld->threadId);
            bool found;
            vector<Lock*>::const_iterator lookup = 
                find_if(allLocks.begin(), allLocks.end(), lock_has_addr(memoryWrite->effective_address));
            if(lookup==allLocks.end())
                found = false;
            else
                found = (*lookup)->isLocked;
            PIN_ReleaseLock(&GlobalLock);

            if(value==0 && found){
                lockMemoryWrite = memoryWrite;
                tld->isZeroAfter = 1;
            }
            if(value==1 && !found){
                lockMemoryWrite = memoryWrite;
                tld->isOneAfterAndUnlocked = 1;
            }
            if(value==1 && found){
                lockMemoryWrite = memoryWrite;
                tld->isOneAfterAndLocked = 1;
            }
            if(value==2 && !found){
                lockMemoryWrite = memoryWrite;
                tld->isTwoAfter = 1;
            }
        }
    }

    int zeroOneLock = tld->isEAXZero && tld->isZeroBefore && tld->isOneAfterAndUnlocked;
    int zeroTwoLock = tld->isEAXTwo && tld->isZeroBefore && tld->isTwoAfter;

    if(zeroOneLock || zeroTwoLock){
        PIN_GetLock(&GlobalLock, tld->threadId);
        tld->out << "Lock Detected" << endl;
        tld->out << INS_Disassemble(ins) << endl;
        tld->currentVectorClock->event();
        tld->out << lockMemoryWrite->effective_address << endl;

        set<ADDRINT>::iterator it = writeIntersection.find(lockMemoryWrite->effective_address);
        if(it != writeIntersection.end())
            writeIntersection.erase(it);
        vector<Lock*>::const_iterator lookup = 
                find_if(allLocks.begin(), allLocks.end(), lock_has_addr(lockMemoryWrite->effective_address));
        if(lookup==allLocks.end()){
            Lock *l = new Lock(lockMemoryWrite->effective_address);
            l->lock_it(tld->insCount);
            allLocks.push_back(l);
            l->lockVectorClock->receiveAction(tld->currentVectorClock);
            tld->acqLocks.push_back(l);
        }
        else{
            (*lookup)->lock_it(tld->insCount);
            (*lookup)->lockVectorClock->receiveAction(tld->currentVectorClock);
            tld->acqLocks.push_back((*lookup));
        }
        PIN_ReleaseLock(&GlobalLock);
    }

    int zeroOneUnlock = tld->isOneBeforeAndLocked && tld->isZeroAfter;
    int twoOneUnlock = tld->isTwoBefore && tld->isOneAfterAndLocked;
    int twoZeroUnlock = tld->isTwoBefore && tld->isZeroAfter;

    if(zeroOneUnlock || twoOneUnlock || twoZeroUnlock){
        PIN_GetLock(&GlobalLock, tld->threadId);
        tld->out << "Unlocked" << endl;
        tld->currentVectorClock->event();
        tld->out << INS_Disassemble(ins) << endl;
        tld->out << lockMemoryWrite->effective_address << endl; 

        vector<Lock*>::const_iterator lookup = 
                find_if(allLocks.begin(), allLocks.end(), lock_has_addr(lockMemoryWrite->effective_address));
        if(lookup!=allLocks.end()){
            (*lookup)->unlock_it(tld->insCount);
            (*lookup)->lockVectorClock->receiveAction(tld->currentVectorClock);

            for(unsigned i=0; i< (*lookup)->recordClocks.size(); ++i){
                tld->out << "********************************" << endl;
                tld->out << "Locked Region " << i << endl;
                set<ADDRINT> readRegion = (*lookup)->atomicReadRegions[i];
                set<ADDRINT> writeRegion = (*lookup)->atomicWriteRegions[i];
                set<ADDRINT> out1;
                set<ADDRINT> out2;
                set<ADDRINT> out3;
                set_intersection(readRegion.begin(), readRegion.end(), 
                                 (*lookup)->memWriteAccesses.begin(), (*lookup)->memWriteAccesses.end(), 
                                 inserter(out1, out1.begin()));
                set_intersection(writeRegion.begin(), writeRegion.end(), 
                                 (*lookup)->memReadAccesses.begin(), (*lookup)->memReadAccesses.end(), 
                                 inserter(out2, out2.begin()));
                set_intersection(writeRegion.begin(), writeRegion.end(), 
                                 (*lookup)->memWriteAccesses.begin(), (*lookup)->memWriteAccesses.end(), 
                                 inserter(out3, out3.begin()));
                PRINT_ELEMENTS(out1, tld, "Rprev-Wcurr: ");
                PRINT_ELEMENTS(out2, tld, "Wprev-Rcurr: ");
                PRINT_ELEMENTS(out3, tld, "Wprev-Wcurr: ");
                tld->out << "***********************************" << endl;
                if((!out1.empty()) || (!out2.empty()) || (!out3.empty())){
                    tld->currentVectorClock->receiveAction(&((*lookup)->recordClocks[i]));
                }
            }

            (*lookup)->recordClocks.push_back(*((*lookup)->lockVectorClock));
            (*lookup)->atomicReadRegions.push_back((*lookup)->memReadAccesses);
            (*lookup)->atomicWriteRegions.push_back((*lookup)->memWriteAccesses);
            PRINT_ELEMENTS((*lookup)->memReadAccesses, tld, "Reads: ");
            PRINT_ELEMENTS((*lookup)->memWriteAccesses, tld, "Writes: ");

            updateMemoryClocks(tld, (*lookup));

            (*lookup)->memReadAccesses.clear();
            (*lookup)->memWriteAccesses.clear();
            list<Lock*>::iterator acqLock = 
                find_if(tld->acqLocks.begin(), tld->acqLocks.end(), lock_has_addr((*lookup)->addr));
            if(acqLock!=tld->acqLocks.end())
                tld->acqLocks.erase(acqLock);
        }
        PIN_ReleaseLock(&GlobalLock);
    }
    tld->resetVars();
    PIN_UnlockClient();
}

void check_lock(INS ins)
{
    UINT32 num_operands = INS_OperandCount(ins);
    UINT32 i;
    for (i = 0; i < num_operands; ++i) {
        if (INS_OperandWritten(ins, i)) {
            if (INS_OperandIsReg(ins, i)) {
                REG _reg = INS_OperandReg(ins, i);
                if (_reg != REG_INVALID() && _reg < REG_MM_BASE) {
                    INS_InsertCall(ins, 
                                   IPOINT_BEFORE, 
                                   (AFUNPTR) CheckCMPXCHG, 
                                   IARG_THREAD_ID, 
                                   IARG_PTR, ins, 
                                   IARG_END);

                    INS_InsertCall(ins, 
                                   IPOINT_BEFORE, 
                                   (AFUNPTR) CheckEAX, 
                                   IARG_THREAD_ID, 
                                   IARG_REG_VALUE, _reg, 
                                   IARG_PTR, _reg, 
                                   IARG_PTR, ins, 
                                   IARG_END);
                }
            }
            else if (INS_OperandIsMemory(ins, i)) {
                // Insert a call before to get the effective address and the size.
                INS_InsertCall(ins, 
                               IPOINT_BEFORE, 
                               (AFUNPTR) SetUpMemoryParams, 
                               IARG_THREAD_ID, 
                               IARG_MEMORYWRITE_EA, 
                               IARG_MEMORYWRITE_SIZE, 
                               IARG_END);
                // Insert a call before to get the value before.
                INS_InsertCall(ins, 
                               IPOINT_BEFORE, 
                               (AFUNPTR) RecordMemoryWriteBeforeINS, 
                               IARG_THREAD_ID,
                               IARG_PTR, ins, 
                               IARG_END);
                // Insert a call after to get the value written.
                INS_InsertCall(ins, 
                               IPOINT_AFTER, 
                               (AFUNPTR) RecordMemoryWriteAfterINS, 
                               IARG_THREAD_ID, 
                               IARG_PTR, ins, 
                               IARG_END);
            }
        } 
    }
}

VOID incrementThreadINS(THREADID tid, INS ins){
    ThreadLocalData *tld = getTLS(tid);
    tld->insCount++;
    if(picked_races)
 {
  if((tid==tid1)&&(i_count1==tld->insCount)&&(!waiting))
  {
        waiting=true;
  //  cout << "wait "<<tid1<<" "<<tid2<<" "<<i_count1<<" "<<i_count2<<" "<< endl;
    sem_wait(&sem) ;
   }

  if((tid==tid2)&&(i_count2==tld->insCount)) 
  {
  //  cout << "post "<<tid2<< endl;
    sem_post(&sem);
    waiting=false;
  }
  cout << tid <<" "<< tld->insCount<<endl;
 }
 
if(picked_relax)
{
 if((tid==tid1)&&(i_count1==tld->insCount)&&(!insert))
{
insert=true;
d.interleave();
cout<<"relaxed"<<endl;
  cout << tid <<" "<< tld->insCount<<endl;
}

if((tid==tid2)&&(i_count2==tld->insCount)) 
{
INS_Delete(ins);
}
}
}
 
		

VOID MemoryReadInst(THREADID threadid, ADDRINT effective_address, int i, INS ins){
    execution_element read_element;
    list<MemoryAddr*>::const_iterator lookup = 
                find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if(lookup!=memSet.end()){
      //  cout << " EA "<<effective_address<<endl;
        ThreadLocalData* tld = getTLS(threadid);
        PIN_GetLock(&GlobalLock, tld->threadId);
        sharedAccesses << tld->threadId << " " << tld->insCount << " r " << effective_address << "," << endl;
        PIN_ReleaseLock(&GlobalLock);
        tld->addAddressToLockRead(effective_address);
        tld->currentVectorClock->event();
        PIN_GetLock(&((*lookup)->MemoryLock), tld->threadId);
        (*lookup)->operand_index.push_back(i);
        (*lookup)->accesses.push_back('r');
        (*lookup)->accessingThread.push_back(threadid);
        (*lookup)->accessingInstructions.push_back(tld->insCount);
        (*lookup)->accessClocks.push_back(*(tld->currentVectorClock));
	read_element.tid = threadid;
	read_element.vc = tld->currentVectorClock;
	read_element.ins = INS_Disassemble(ins_send);
	read_element.addr = effective_address;
	read_element.i_count = tld->insCount;
	read_element.type = 'r';
	for(int i=0; i<execution_history.size(); i++){
	//    cout << execution_history[i].addr << " " << effective_address <<endl;
            if((execution_history[i].addr == effective_address)&&(execution_history[i].type=='w')&&((execution_history[i].vc)->areConcurrent (tld->currentVectorClock))&&(execution_history[i].tid!=threadid))
		 {
		execution_element event1, event2;
		event1.tid = execution_history[i].tid;
		event1.addr = execution_history[i].addr;
		event1.type = 'w';
		event1.i_count = execution_history[i].i_count;
		event1.vc = execution_history[i].vc;
		event1.ins = execution_history[i].ins;
		event2 = read_element;
	        data_race.push_back({event1, event2});/*Record racing instructions*/
		file_races << event1.tid << " " << event1.i_count << " " << event2.tid << " " << event2.i_count << endl;
		}
	}
	execution_history.push_back(read_element); /*Record execution sequence */
        PIN_ReleaseLock(&((*lookup)->MemoryLock));
     }

}

VOID MemoryWriteInst(THREADID threadid, ADDRINT effective_address, int i){

    execution_element write_element;
    list<MemoryAddr*>::const_iterator lookup = 
                find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if(lookup!=memSet.end()){
       //  cout << " EA "<<effective_address<<endl;
        ThreadLocalData* tld = getTLS(threadid);
        PIN_GetLock(&GlobalLock, tld->threadId);
        sharedAccesses << tld->threadId << " " << tld->insCount << " w " << effective_address << "," << endl;
        PIN_ReleaseLock(&GlobalLock);
        tld->addAddressToLockWrite(effective_address);
        tld->currentVectorClock->event();
        PIN_GetLock(&((*lookup)->MemoryLock), tld->threadId);
        (*lookup)->accesses.push_back('w');
        (*lookup)->operand_index.push_back(i);
        (*lookup)->accessingThread.push_back(threadid);
        (*lookup)->accessingInstructions.push_back(tld->insCount);
        (*lookup)->accessClocks.push_back(*(tld->currentVectorClock));
	write_element.tid = threadid;
	write_element.vc = tld->currentVectorClock;
	write_element.ins = INS_Disassemble(ins_send);
	write_element.addr = effective_address;
	write_element.i_count = tld->insCount;
	write_element.type = 'w';
	for(int i=0; i<execution_history.size(); i++){
	   // cout << execution_history[i].addr << " " << effective_address <<endl;
            if((execution_history[i].addr == effective_address)&&((execution_history[i].vc)->areConcurrent (tld->currentVectorClock))&&(execution_history[i].tid!=threadid))
		 {
		execution_element event1, event2;
		event1.tid = execution_history[i].tid;
		event1.addr = execution_history[i].addr;
		event1.type = execution_history[i].type;
		event1.i_count = execution_history[i].i_count;
		event1.vc = execution_history[i].vc;
		event1.ins = execution_history[i].ins;
		event2 = write_element;
	        data_race.push_back({event1, event2});
		file_races << event1.tid << " " << event1.i_count << " " << event2.tid << " " << event2.i_count << endl;
		}
	}
	execution_history.push_back(write_element);
        PIN_ReleaseLock(&((*lookup)->MemoryLock));

     }

}

void LoadInst(ADDRINT address, THREADID t_id, INS ins, int index)
   { 

     int same=0;
     execution_element store_element;
     ThreadLocalData* tld = getTLS(t_id);
     load.i_count=tld->insCount;
     load.tid=t_id;
     load.addr=address;
     load.vc=tld->currentVectorClock;
     load.type='r';
     load.ins=ins_l; 
  map<THREADID, vector<execution_element>>::iterator iter2 = buffers.find(t_id);
  if (iter2 != buffers.end() ){
  if (iter2->second.size()>0)
         {
           for (j=iter2->second.size()-1;j>=0;j--)
             {	
	       ThreadLocalData* tld2 = getTLS(iter2->second[j].tid);
               string s1= std::to_string(iter2->second[j].addr) ;
               string s2=std::to_string(address);
               uint64_t u1=store_buffer[j].addr;
               uint64_t u2=address;
               if((s1.compare(s2)!=0) && ((tld->currentVectorClock)->areConcurrent ((iter2->second[j].vc))))
                  {
                  place=j;
            if(place>=0){ 
            ThreadLocalData* tld2 = getTLS(iter2->second[place].tid);
            if(place!=-1){
             store_element.i_count=iter2->second[place].i_count;
             store_element.tid=iter2->second[place].tid;
             store_element.addr=iter2->second[place].addr;
             store_element.vc=tld2->currentVectorClock;//store_buffer[place].vc;
             store_element.ins=iter2->second[place].ins;
             store_element.type='w';
             table.push_back({load, store_element});
	     relax_tso.push_back({load, store_element});
//	     relax_pso.push_back({load, store_element});
             file << store_element.tid << " " << store_element.i_count << " " << store_element.addr << " " ;
             file << load.tid << " " << load.i_count << " " << load.addr << "\n";
	     file_relax << load.tid << " " << load.i_count << " " << load.ins << " $$$ " << store_element.tid << " " << store_element.i_count << " " << store_element.ins<< endl;
             instruction << store_element.ins << " $$$ " << load.ins << "\n";
             place=-1;
          }   
       }
                    }
	   else
 		break;
              }

     store_buffer.clear();
    }
  }

}
void StoreInst(ADDRINT address, THREADID t_id,INS ins, int index)
   {

    string addr=std::to_string(address);
    map<THREADID, vector<execution_element>>::iterator iter = buffers.find(t_id);
    map<THREADID, vector<execution_element>>::iterator iterx = buffers_tso.find(t_id);
    ThreadLocalData* tld = getTLS(t_id);
    if(iterx != buffers_tso.end())
    {
     execution_element buffer_element;
     buffer_element.i_count=tld->insCount;
     buffer_element.tid=t_id;
     buffer_element.addr=address;
     buffer_element.ins=ins_s;
     buffer_element.type='w';
    //store.ins=INS_Disassemble(ins);
     buffer_element.vc=tld->currentVectorClock;
     buffers_tso[t_id].push_back(buffer_element);
     for(int i=buffers_tso[t_id].size()-2;(i>=0)&&(i>=buffers_tso[t_id].size()-window_size);i--)
     {
      //check for tso reordering here
	if((buffer_element.addr!=buffers_tso[t_id][i].addr) && ((tld->currentVectorClock)->areConcurrent (buffers_tso[t_id][i].vc)))
	{
	    file_relax << buffers_tso[t_id][i].tid << " " << buffers_tso[t_id][i].i_count << " " << buffers_tso[t_id][i].ins << " $$$ "  << buffer_element.tid << " " << buffer_element.i_count << " " << buffer_element.ins << endl;
	}
	else
	    break;
     }

     }
     else
     {
     vector<execution_element> newbuffer_tso;
     execution_element buffer_element;
     buffer_element.i_count=tld->insCount;
     buffer_element.tid=t_id;
     buffer_element.addr=address;
     buffer_element.ins=ins_s;
     buffer_element.type='w';
    //store.ins=INS_Disassemble(ins);
     buffer_element.vc=tld->currentVectorClock;
     newbuffer_tso.push_back(buffer_element);
     buffers_tso[t_id]=newbuffer_tso;
     }



    if(iter != buffers.end())
    {
      // map<THREADID, map<string,vector<element>>>::iterator iter_pso = buffer_pso[t_id]->second.find(addr);

     map<string,vector<execution_element>>::iterator iter_pso = buffer_pso[t_id].find(addr);

   if(iter_pso != buffer_pso[t_id].end())
    {  
    store.i_count=tld->insCount;
    store.tid=t_id;
    store.addr=address;
    store.ins=ins_s;
    store.type='w';
    //store.ins=INS_Disassemble(ins);
    store.vc=tld->currentVectorClock;
    iter_pso->second.push_back(store); 
     }
   else
   {
    vector<execution_element> newbuffer_pso;
    execution_element newelement_pso;
    newelement_pso.i_count=tld->insCount;
    newelement_pso.tid=t_id;
    newelement_pso.addr=address;
    newelement_pso.ins=ins_s;
    newelement_pso.type='w';
    //newelement.ins=INS_Disassemble(ins);
    newelement_pso.vc=tld->currentVectorClock;
    newbuffer_pso.push_back(newelement_pso);
    buffer_pso[t_id].insert( std::pair<string,vector<execution_element>>(addr,newbuffer_pso) );
    }
    }
    else
    {/*If buffer_pso has no entry for thread with id : t_id*/
      vector<execution_element> newbuffer_pso;
    map< string,vector<execution_element>> newentry;
    execution_element newelement_pso;
    newelement_pso.i_count=tld->insCount;
    newelement_pso.tid=t_id;
    newelement_pso.addr=address;
    newelement_pso.ins=ins_s;
    newelement_pso.type='w';
    //newelement.ins=INS_Disassemble(ins);
    newelement_pso.vc=tld->currentVectorClock;
    newbuffer_pso.push_back(newelement_pso);
    newentry.insert( std::pair<string,vector<execution_element>>(addr,newbuffer_pso) );
    buffer_pso.insert(std::pair<THREADID,map< string,vector<execution_element>>>(t_id,newentry));
     }
    if (iter == buffers.end() )
    {
    vector<execution_element> newbuffer;
    execution_element newelement;
    newelement.i_count=tld->insCount;
    newelement.tid=t_id;
    newelement.addr=address;
    newelement.ins=ins_s;
    //newelement.ins=INS_Disassemble(ins);
    newelement.vc=tld->currentVectorClock;
    newbuffer.push_back(newelement);
    buffers[t_id]=newbuffer;
    }
     else{
    //vector<element> oldbuffer;
    //oldbuffer=iter->second;
    store.i_count=tld->insCount;
    store.tid=t_id;
    store.addr=address;
    store.ins=ins_s;
    //store.ins=INS_Disassemble(ins);
    store.vc=tld->currentVectorClock;
    iter->second.push_back(store); 
       

//oldbuffer.push_back(store);
}
    map<THREADID, vector<execution_element>>::iterator iter2 = buffers.find(t_id);  
       // store_buffer.push_back(store);
       // if (window>=window_size)
    if (iter2->second.size()>window_size)
           {
             iter2->second.erase(iter2->second.begin());
            //push_store();
            // window--;
            }
     // window++;

//cout << "store: " << ins_s<< endl; 
}


void rec_mem(INS ins){
string ins2;
    INS_InsertCall(ins, 
                   IPOINT_BEFORE,
                   (AFUNPTR) incrementThreadINS, 
                   IARG_THREAD_ID,
                   IARG_PTR, ins,
                   IARG_END);
UINT32 num_operands = INS_MemoryOperandCount(ins);
    UINT32 i;
    ins_send= ins;
    for (i = 0; i < num_operands; ++i){
        if(INS_MemoryOperandIsRead(ins, i)){
            INS_InsertCall(ins, 
                           IPOINT_BEFORE,
                           (AFUNPTR) MemoryReadInst, 
                           IARG_THREAD_ID, 
                           IARG_MEMORYOP_EA, i,
                           IARG_UINT32,i,
                           IARG_END);
         
if(INS_Mnemonic(ins)=="MOV")              
  {
ins_l= INS_Disassemble(ins);
//cout << "Load1: " << INS_Disassemble(ins) <<" " <<INS_Mnemonic(ins)<< endl; 
                      INS_InsertCall(ins, 
                           IPOINT_BEFORE,
                           (AFUNPTR) LoadInst, 
                           IARG_MEMORYOP_EA, i,
                           IARG_THREAD_ID,
                           // IARG_PTR,ins2, 
                           IARG_PTR, ins, 
                           IARG_UINT32,i,
                           IARG_END);
//cout << "Load2: " << INS_Disassemble(ins) <<" " <<INS_Mnemonic(ins)<< endl; 
                }
        }

        if(INS_MemoryOperandIsWritten(ins, i)){

            INS_InsertCall(ins, 
                           IPOINT_BEFORE,
                           (AFUNPTR) MemoryWriteInst, 
                           IARG_THREAD_ID, 
                           IARG_MEMORYOP_EA, i,
                           IARG_UINT32,i,
                           IARG_END);

           // if(INS_IsMov(ins))
if(INS_Mnemonic(ins)=="MOV")             
  {
ins_s= INS_Disassemble(ins);
//cout << "store1: " << INS_Disassemble(ins) <<" " <<INS_Mnemonic(ins)<< endl; 
                      INS_InsertCall(ins, 
                           IPOINT_BEFORE,
                           (AFUNPTR) StoreInst, 
                           IARG_MEMORYOP_EA, i,
                           IARG_THREAD_ID,
                            //IARG_PTR,ins2,
                           IARG_PTR, ins, 
                           IARG_UINT32,i,
                           IARG_END);
//cout << "store2: " << INS_Disassemble(ins) <<" " <<INS_Mnemonic(ins)<< endl; 
                }
        }
    }
}


VOID Trace(TRACE trace, VOID *val)
{
    if (!filter.SelectTrace(trace))
        return;
  //  cout << "before" << endl;
    std::ifstream file1("file_races.txt");
    std::ifstream file2("file_relax.txt");
    FILE * pFile;
    FILE * pFile2;
    pFile = fopen ( "file_relax.txt" , "r" );
    pFile2 = fopen ( "file_races.txt" , "r" );
    fseek(pFile, 0, SEEK_END);
    fseek(pFile2, 0, SEEK_END); 
    if(!((picked_races)||(picked_relax)||(first_run))){
    if ((ftell(pFile) == 0)&&(ftell(pFile2) == 0)&&(!first_run)) {    
    cout <<"eeeeemmmppptttyy\n";
    first_run=true;
    }
      else if((!first_run)&&(ftell(pFile) != 0)&&(!picked_races)&&(!picked_relax)&&(false))/*picking from races*/
    {  int oldpos=0;
       int newpos=0; 
    int k=0; 
       string arr[4]; 
     string sLine;
     getline(file1, sLine);
     picked_races=true;
     cout<<sLine<<endl;
     for(int i=0;i<sLine.length();i++)
     {
      if(sLine[i]==' ')
      {newpos=i;
       arr[k]= sLine.substr(oldpos,newpos-oldpos);
       oldpos=newpos+1;
       cout << arr[k] << endl;
      k++;
      }
     arr[k]=sLine.substr(oldpos,newpos-oldpos);
     }
     tid1=stoi(arr[0]);
     tid2=stoi(arr[2]);
     i_count1=stoi(arr[1]);
     i_count2=stoi(arr[3]);
    }
    else if((!first_run)&&(ftell(pFile2) != 0)&&(!picked_races)&&(!picked_relax))/*picking from relax*/
    { 
     int newpos=0;
     int oldpos=0;
     int k = 0;
     string arr[6]; 
     string sLine;
     getline(file2, sLine);  
     picked_relax=true;
     std::size_t found = sLine.find(" $$$ ");
          for(int i=0;i<sLine.length();i++)
     {
         if ((found!=std::string::npos)&&(k==2))
      {
      arr[k]=sLine.substr(oldpos,found-oldpos);
      i=found+5;
      oldpos=i;
          k++;
       }
      else if (k==5)
      {
      arr[k]=sLine.substr(oldpos,sLine.length()-oldpos);
      i=sLine.length();
       k++;
      }
      else if((sLine[i]==' ')&&((k==0)||(k==1)||(k==3)||(k==4)))
      {    
       newpos=i;
       arr[k]= sLine.substr(oldpos,newpos-oldpos);
       oldpos=newpos+1;
       k++;
      }
     }
    tid1=stoi(arr[0]);
    i_count1=stoi(arr[1]);
    ins1=arr[2];
    tid2=stoi(arr[3]);
    i_count2=stoi(arr[4]);
    ins2=arr[5];

    }}
    fclose ( pFile );
    fclose ( pFile2 );
//cout << "after"<<endl;
    PIN_GetLock(&GlobalLock, -1);
    ThreadLocalData *tld = getTLS(mapOfThreadIDs[PIN_GetTid()]);
    PIN_ReleaseLock(&GlobalLock);
 
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
           if(INS_IsAtomicUpdate(ins)){
            check_lock(ins);
            }
            rec_mem(ins);
            tld->thread_trace << INS_Disassemble(ins) << endl;
        }
    }
}


VOID Fini(INT32 code, void *v){
    file.close();
    instruction.close(); 
    file_races.close();
    file_relax.close();
    list<MemoryAddr *>::const_iterator i;
    for(i=memSet.begin(); i!=memSet.end(); i++){
        cout << "**********************************" << endl;
        cout << (*i)->addr << endl;

        int size = (*i)->accesses.size();
        int k;
        for(k=0; k < size; k++){
            cout << k << ": " << endl;
            cout << (*i)->accessingThread[k] << endl;
            cout << (*i)->accessingInstructions[k] << endl;
            cout << (*i)->accesses[k] << endl;
            
            int j;
            for(j=0; j<totalThreads; j++){
                cout << (*i)->accessClocks[k].vclock_arr[j] << " ";
            }
            cout <<endl;
        }
    }
    for(i=memSet.begin(); i!=memSet.end(); i++){
        int size = (*i)->accesses.size();
        int k;
        for(k=0; k < size; k++){
            int j;
            for(j=k+1; j < size; j++){
                if(j==k)
                    continue;
                if((*i)->accesses[k]=='w' || (*i)->accesses[j]=='w'){
                    if((*i)->accessClocks[k].areConcurrent(&((*i)->accessClocks[j]))){
                      //  races << "**********************************" << endl;
                        //races << (*i)->addr << endl;
                        //races << "Race Detected" << endl;
                        races << (*i)->accessingThread[k] << 
                                 " " << (*i)->accessingInstructions[k] <<
                                 " " << (*i)->accesses[k] << " " /*<< (*i)->operand_index[k] << " " */<< (*i)->accessingThread[j] << 
                                 " " << (*i)->accessingInstructions[j] <<
                                 " " << (*i)->accesses[j] << /*" " << (*i)->operand_index[j] <<*/ endl;
                       
                    }
                }
            }
        }
    }
}

INT32 Usage()
{
    cerr <<
        "This pin tool tries to find the locks and unlocks in a program.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

void load_read_write_sets(){
    string line;
    ifstream writeins("writeSetIntersection.out");
    for (unsigned int i=1; getline(writeins, line); ++i){
        writeIntersection.insert(atoll(line.c_str()));
        MemoryAddr* mem = new MemoryAddr(atoll(line.c_str()));
        memSet.push_back(mem);
    }
}

int main(int argc, char * argv[])
{
    sem_init(&sem, 0, 0);
    load_read_write_sets();
    sharedAccesses.open("sharedAccesses.out");
    races.open("races.out");
    allLocks.reserve(20);
    file.open("table.txt");
    instruction.open("instruction.txt");
    file_races.open("file_races.txt",std::ios::app);
    file_relax.open("file_relax.txt",std::ios::app);
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

  //  pinplay_engine.Activate(argc, argv,
    //  KnobPinPlayLogger, KnobPinPlayReplayer);
    
    tls_key = PIN_CreateThreadDataKey(0);
    PIN_InitLock(&GlobalLock);

    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddFiniFunction(Fini, 0);

    filter.Activate();

    PIN_StartProgram();
    return 0;
}
//	7291A1 
