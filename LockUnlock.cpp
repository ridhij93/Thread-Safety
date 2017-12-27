#include "definitions.h"
#include "ThreadLocalData.h"
//#include "ThreadLocalBuffer.h"
#include "Lock.h"
#include "pinplay.H"
#include "MemoryAddr.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#define window_size 4
PINPLAY_ENGINE pinplay_engine;
KNOB<BOOL> KnobPinPlayLogger(KNOB_MODE_WRITEONCE,
                      "pintool", "log", "0",
                      "Activate the pinplay logger");

KNOB<BOOL> KnobPinPlayReplayer(KNOB_MODE_WRITEONCE,
                      "pintool", "replay", "0",
                      "Activate the pinplay replayer");
int j;
ofstream file;
ofstream instruction;
string ins_l,ins_s;
int place=-1;
struct element
{
THREADID tid;
int i_count;
string ins;
ADDRINT addr;
VectorClock* vc;
};
element store;
element load;
vector<pair<element,element>> table;
vector<element> store_buffer;
map<THREADID, vector<element>> buffers;
map<THREADID,map< string,vector<element>>> buffer_pso;

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
            // tld->out << "**********************" << endl;
            // tld->out << INS_Disassemble(ins) << endl;
            // tld->out << memoryWrite->effective_address << endl;
            // tld->out << value << endl;
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
    //tld->thread_trace << INS_Disassemble(ins).c_str() << endl;
}


VOID MemoryReadInst(THREADID threadid, ADDRINT effective_address, int i ){
    list<MemoryAddr*>::const_iterator lookup = 
                find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if(lookup!=memSet.end()){
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
        PIN_ReleaseLock(&((*lookup)->MemoryLock));
     }
}

VOID MemoryWriteInst(THREADID threadid, ADDRINT effective_address, int i){
    list<MemoryAddr*>::const_iterator lookup = 
                find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if(lookup!=memSet.end()){
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
        PIN_ReleaseLock(&((*lookup)->MemoryLock));
     }
}
void incr_ins(INS ins){
mtx.lock();
totalins++;
mtx.unlock();
}




void LoadInst(ADDRINT address, THREADID t_id, INS ins, int index)
   { int same=0;
     element store_element;
     ThreadLocalData* tld = getTLS(t_id);
     load.i_count=tld->insCount;
     load.tid=t_id;
     load.addr=address;
     load.vc=tld->currentVectorClock;
     //load.ins=INS_Disassemble(ins);
     load.ins=ins_l; 
  map<THREADID, vector<element>>::iterator iter2 = buffers.find(t_id);
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
             //  cout << "before "<< j << " " << window << s1 << " " << s2 <<endl;
             // if(s1.compare(s2)!=0){
               //  same=1;}
               if((s1.compare(s2)!=0) && ((tld->currentVectorClock)->areConcurrent ((tld2->currentVectorClock))))
                  {
                      place=j;
                    }
              }
          if(place>=0){ 
          ThreadLocalData* tld2 = getTLS(iter2->second[place].tid);
          if(place!=-1){
             store_element.i_count=iter2->second[place].i_count;
             store_element.tid=iter2->second[place].tid;
             store_element.addr=iter2->second[place].addr;
             store_element.vc=tld2->currentVectorClock;//store_buffer[place].vc;
             store_element.ins=iter2->second[place].ins;
             table.push_back({load,store_element});
             file << store_element.tid << " " << store_element.i_count << " " << store_element.addr << " " ;
             file << load.tid << " " << load.i_count << " " << load.addr << "\n";
             instruction << store_element.ins << " $$$ " << load.ins << "\n";
             place=-1;
          }   
       }
    
     store_buffer.clear();
  
//push_store();
   }}
//cout << "Load: " << ins_l<< endl; 
  // window=0;
//cout << "Load: " << INS_Disassemble(ins) <<" " <<INS_Mnemonic(ins)<< endl; 
}
void StoreInst(ADDRINT address, THREADID t_id,INS ins, int index)
   {
   string addr=std::to_string(address);
    
    map<THREADID, vector<element>>::iterator iter = buffers.find(t_id);
    ThreadLocalData* tld = getTLS(t_id);
    if(iter != buffers.end())
    {
      // map<THREADID, map<string,vector<element>>>::iterator iter_pso = buffer_pso[t_id]->second.find(addr);

     map<string,vector<element>>::iterator iter_pso = buffer_pso[t_id].find(addr);

   if(iter_pso != buffer_pso[t_id].end())
 {  
   store.i_count=tld->insCount;
    store.tid=t_id;
    store.addr=address;
    store.ins=ins_s;
    //store.ins=INS_Disassemble(ins);
    store.vc=tld->currentVectorClock;
    iter_pso->second.push_back(store); 
     }
   else
   {
    vector<element> newbuffer_pso;
    element newelement_pso;
    newelement_pso.i_count=tld->insCount;
    newelement_pso.tid=t_id;
    newelement_pso.addr=address;
    newelement_pso.ins=ins_s;
    //newelement.ins=INS_Disassemble(ins);
    newelement_pso.vc=tld->currentVectorClock;
    newbuffer_pso.push_back(newelement_pso);
    buffer_pso[t_id].insert( std::pair<string,vector<element>>(addr,newbuffer_pso) );
    }
    }
    else
    {/*If buffer_pso has no entry for thread with id : t_id*/
      vector<element> newbuffer_pso;
    map< string,vector<element>> newentry;
    element newelement_pso;
    newelement_pso.i_count=tld->insCount;
    newelement_pso.tid=t_id;
    newelement_pso.addr=address;
    newelement_pso.ins=ins_s;
    //newelement.ins=INS_Disassemble(ins);
    newelement_pso.vc=tld->currentVectorClock;
    newbuffer_pso.push_back(newelement_pso);
    newentry.insert( std::pair<string,vector<element>>(addr,newbuffer_pso) );
    buffer_pso.insert(std::pair<THREADID,map< string,vector<element>>>(t_id,newentry));
     }
    if (iter == buffers.end() )
    {
    vector<element> newbuffer;
    element newelement;
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
    map<THREADID, vector<element>>::iterator iter2 = buffers.find(t_id);  
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
INS_InsertCall(ins, 
                   IPOINT_BEFORE,
                   (AFUNPTR) incr_ins, 
                   IARG_PTR, ins,
                   IARG_END); 

//cout << "Load main: " << INS_Disassemble(ins) <<" " <<INS_Mnemonic(ins)<< endl;
    UINT32 num_operands = INS_MemoryOperandCount(ins);
    UINT32 i;
    for (i = 0; i < num_operands; ++i){
        if(INS_MemoryOperandIsRead(ins, i)){
            INS_InsertCall(ins, 
                           IPOINT_BEFORE,
                           (AFUNPTR) MemoryReadInst, 
                           IARG_THREAD_ID, 
                           IARG_MEMORYOP_EA, i,
                           IARG_UINT32,i,
                           IARG_END);
           //  if(INS_IsMov(ins))
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


//CODECACHE_CreateNewCacheBlock (sizeof(element) * 4);
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

//for (unsigned i=0; i<table.size(); i++)
  //  std::cout << " " << table[i].first.ins<< " "<< table[i].second.ins<< endl;

cout << "total ins : " << totalins <<endl;
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
CODECACHE_ChangeMaxInsPerTrace 	(4);
    load_read_write_sets();
    sharedAccesses.open("sharedAccesses.out");
    races.open("races.out");
    allLocks.reserve(20);
    file.open("table.txt");
    instruction.open("instruction.txt");
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    pinplay_engine.Activate(argc, argv,
      KnobPinPlayLogger, KnobPinPlayReplayer);
    
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
