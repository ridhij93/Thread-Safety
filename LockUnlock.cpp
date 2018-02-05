/*trace the prev details: if done is found after any race remove that done and replay races */


#include "definitions.h"
#include "ThreadLocalData.h"
#include "Lock.h"
#include "pinplay.H"
#include "MemoryAddr.h"
#include <mutex>
#include <cstdlib>
#include <unistd.h>
#include <stdlib.h>
#include <string> 
#include <deque>
#include <semaphore.h>
#define window_size 3
//PINPLAY_ENGINE pinplay_engine;
//KNOB<BOOL> KnobPinPlayLogger(KNOB_MODE_WRITEONCE,
  //                    "pintool", "log", "0",
    //                  "Activate the pinplay logger");

//KNOB<BOOL> KnobPinPlayReplayer(KNOB_MODE_WRITEONCE,
  //                    "pintool", "replay", "0",
    //                  "Activate the pinplay replayer");

// Contains knobs to filter out things to instrument
FILTER filter;
ofstream runfrom;
int window=0;
bool all=false;
bool wait_t1=false;
bool post_t2=false;
bool last_waiting=false;
int race_point=0;
int last_ins=0;
bool only_race=false;
string detail_s="";
int sem_count=0;
string s="";
int last0=0;
vector<bool> thread_fini;
bool stack_end=false;
bool finished=false;
int split=0;
int thread_count;
bool done=true;
int tid1,tid2,count1,count2;
string target="";
sem_t sem,dep,rev,wait_last;
string state1, state2;
vector<Lock*> allLocks;
list<MemoryAddr*> memSet;
bool first_run=false;
bool reverse_point=false;
int totalThreads = 0;
int totalins = 0;
PIN_LOCK GlobalLock;
TLS_KEY tls_key;
std::mutex mtx;
string bt_string="";
set<ADDRINT> writeIntersection;
string event;

map<THREADID, THREADID> mapOfThreadIDs;

ofstream sharedAccesses;
ofstream races;
ofstream bt;
ofstream details;
vector<string> prev_exec;
vector<string> execution;
struct sema
{
sem_t s;
int wait=0;
};

deque<sema> semaphores;
vector<deque<int>> order;

struct state
{
int tid;
int count;
bool invert=false;
bool done=false;
};
state curr_state,next_state;
deque<state> stack;
bool executed=false;
bool waited=false;
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
        //cout <<"here"<< endl;
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
    all=true;
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
    if(!first_run)
    {
     thread_fini[threadid]=true; 
       {
	for(int i=1;i<thread_count;i++)
	{
	 if(!thread_fini[i])
 	  { 
	    all=false;
	    break; 
		}
	 }
    if (all)
	{
	 sem_post(&wait_last);
	 }   
	} 
    } 

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
    if(tid==0)
    {
//cout <<tld->insCount<<" ********************************************************* "<<last0<<endl;
    last_ins++;
    }
    if((!first_run)&&(tid==0)&&(tld->insCount>=last0-1))
    {
    cout<<"put to wait"<<tid <<" "<<tld->insCount<<" "<<tid<<endl;
      for(int i=1;i<thread_count;i++)
       { 
        if(!thread_fini[i])
         {
         last_waiting = true;
         sem_wait(&wait_last);
         }
   


    }
     }
cout << first_run << finished <<stack_end <<wait_t1<<post_t2<<endl;
    if((!first_run)&&(!finished)&&(!stack_end)){   
     cout<<tid <<" "<<tld->insCount<<" "<<curr_state.tid<<" "<<curr_state.count<<" "<<next_state.tid<<" "<<next_state.count<< " "<< order[tid].front()<<endl;  
   if((tid==tid1)&&(tld->insCount==count1))
   { 
    cout<< "############################################ wait* "<< tid1<<" " <<count1<<endl;
    reverse_point=true;
    wait_t1=true;
    string temp1,temp2,temp3;
    temp1=execution[execution.size()-1];
    split=execution.size()-1;
    std::size_t f=temp1.find_first_of('}');
    temp2=temp1.substr(0,f);
    temp3=temp1.substr(f);
    temp1=temp2+","+std::to_string(tid2)+temp3;
    execution[execution.size()-1]=temp1;
    for(int y=0;y<thread_count;y++)
        {
        while(semaphores[y].wait>0)
	{semaphores[y].wait--;
        sem_post(&semaphores[y].s);
	}}
      cout <<"Putting to wait"<<endl;
       sem_wait(&rev);
usleep(1);
    }

   if((tid==tid2)&&(tld->insCount==count2))
   {
    reverse_point=true;
    post_t2=true;
cout<< "############################################ wait "<< tid2<<" " <<count2<<endl;
       for(int y=0;y<thread_count;y++)
        {
        while(semaphores[y].wait>0)
	{semaphores[y].wait--;
        sem_post(&semaphores[y].s);
	}}
      cout <<"Putting to post"<<endl;
    sem_post(&rev);
    }


  if((!reverse_point)&&(!stack_end))
  {
     
    
     if((curr_state.tid==next_state.tid)) 
      {
        while((curr_state.tid==next_state.tid))
	{
          if(stack.size()>=1)
            {
	  cout << "same threads: changing to next" <<endl;
	  curr_state=next_state;
	  stack.pop_front();
	  order[curr_state.tid].pop_front();
	  next_state = stack.front();
	    }
         else
	  {
        if(wait_t1 && post_t2)
	stack_end= true;
	break;
	    }	
      }}
    if((((tld->insCount>=order[tid].front())&&(curr_state.tid==tid)&&(curr_state.count<=tld->insCount)))&&(!executed))
	{
        cout<<"front of current state "<< order[tid].front() <<" "<<tid<<" "<<curr_state.count<<endl;
        cout<<"current tid "<<tid<<endl;
        executed=true;
	while(semaphores[next_state.tid].wait>0)
	 {
	  semaphores[next_state.tid].wait--;
          sem_post(&semaphores[next_state.tid].s);
	 }
	order[tid].pop_front();
	cout<<"top of order's current state "<< order[tid].front() <<" "<<tid<<" "<<curr_state.count<<endl;
 
       }  	
    if((tid==next_state.tid)&&(tld->insCount>=order[next_state.tid].front())&&(!waited)&&(order[next_state.tid].front()!=0))  
	{
        cout << "waiting for next state " << tid <<" " << tld->insCount <<endl;
        waited=true;
	order[tid].pop_front();
	cout << "order after waiting for next state " << tid <<" " << order[tid].front() <<endl;
        if(!executed)
	  {
          while(semaphores[curr_state.tid].wait>0)
           {
	     semaphores[curr_state.tid].wait--;
	     sem_post(&semaphores[curr_state.tid].s);
		} 
          cout << "I am waiting " << tid <<" " << tld->insCount <<endl;
	  semaphores[tid].wait++;
	  sem_wait(&semaphores[tid].s);
	  } 
     /*   for(int p=0;((p<thread_count)&&(p!=tid))||((p=tid)&&(executed));p++)
          {
	    while(semaphores[p].wait>0)
		{	
		semaphores[p].wait--;
		sem_post(&semaphores[p].s);
		}
	   }*/
        }   
    if(((tid==curr_state.tid)||(tid==next_state.tid)) && (tld->insCount>=order[tid].front())&&(order[tid].front()!=0))
     {
        cout << "Same thread waiting " << tid <<" " << tld->insCount <<" " <<order[tid].front()<<endl;         
	semaphores[tid].wait++;
	sem_wait(&semaphores[tid].s);
     }
    if((tid!=curr_state.tid)&&(tid!=next_state.tid)&&(order[tid].front()>0)&&(tld->insCount>=order[tid].front()-1))
	{
        cout << "other thread waiting for next state " << tid <<" " << tld->insCount <<" "<<curr_state.tid<<" "<<next_state.tid<<endl;         
	semaphores[tid].wait++;
	sem_wait(&semaphores[tid].s);
	}
    if(waited && executed)
     {
      //order[curr_state.tid].pop_front();
      //order[next_state.tid].pop_front();
      curr_state=next_state;
      if(stack.size()<=1)
	{
         if(wait_t1 && post_t2)
	stack_end=true;
	}
      stack.pop_front();
      next_state=stack.front();
      curr_state=next_state;
      stack.pop_front();
      next_state=stack.front();             
      cout << "state changing " << curr_state.tid <<" " << next_state.tid <<endl;
      waited=false;
      executed=false;
      cout << curr_state.tid<<" this is the new next state" <<curr_state.count <<endl;
      while(semaphores[curr_state.tid].wait>0)
	{
	cout << curr_state.tid<<" Releasing locks on next state "<<curr_state.count  <<endl;
	semaphores[curr_state.tid].wait--;
	sem_post(&semaphores[curr_state.tid].s);
	}
      }
    }
}
if(!first_run){
 if((((next_state.tid==0)&&(next_state.count==0))||(stack_end)||(reverse_point))||((curr_state.tid==0)&&(curr_state.count==0)))
     {
	if(wait_t1 && post_t2)
      stack_end=true;

      for(int k=0;k<thread_count;k++)
	{
    //  cout<<"releasing in end "<< k <<" "<<thread_fini[k]<<endl;
	if(!thread_fini[k]){
	  while(semaphores[k].wait>0)
 	  {	
	    cout << "in release " << k <<endl;
	    semaphores[k].wait--;
	   // sem_post(&semaphores[k].s);
	   }
	}}}
      }
}
/**************************************/

   

    //tld->thread_trace << INS_Disassemble(ins).c_str() << endl;



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
	event = std::to_string(threadid)+"_"+std::to_string(tld->insCount)+"_"+"r_{"+std::to_string(threadid)+"}_{"+std::to_string(threadid)+"}_{}";
	//bt_string=bt_string+event+" ";	
	execution.push_back(event);        
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
	event = std::to_string(threadid)+"_"+std::to_string(tld->insCount)+"_"+"w_{"+std::to_string(threadid)+"}_{"+std::to_string(threadid)+"}_{}";
	//bt_string=bt_string+event+" ";
	execution.push_back(event); 
        PIN_ReleaseLock(&((*lookup)->MemoryLock));
     }
}

void rec_mem(INS ins){
    INS_InsertCall(ins, 
                   IPOINT_BEFORE,
                   (AFUNPTR) incrementThreadINS, 
                   IARG_THREAD_ID,
                   IARG_PTR, ins,
                   IARG_END);

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

        }

        if(INS_MemoryOperandIsWritten(ins, i)){
            INS_InsertCall(ins, 
                           IPOINT_BEFORE,
                           (AFUNPTR) MemoryWriteInst, 
                           IARG_THREAD_ID, 
                           IARG_MEMORYOP_EA, i,
                           IARG_UINT32,i,
                           IARG_END);
        }
    }
}

VOID Trace(TRACE trace, VOID *val)
{

    if (!filter.SelectTrace(trace))
        return;

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
    string temp=""; 
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
  s=std::to_string((*i)->accessingThread[k])+"_"+  std::to_string((*i)->accessingInstructions[k])+"_"+ (*i)->accesses[k];                 
  for ( int l = 0; l <execution.size(); l++ ) {
      std::size_t index = execution[l].find(s); /*if you find a race, search fot instruction in execution*/
      if ((index!=std::string::npos)&&(index<execution[l].find_first_of('{')))
       { temp=execution[l];
      if((l<=split)||(first_run))
	{
         if((temp.at(temp.length()-2)=='{')&&(temp.at(temp.length()-1)=='}'))
           {
	    temp=temp.substr(0,temp.length()-1);
            temp=temp+std::to_string((*i)->accessingThread[j])+"_"+  std::to_string((*i)->accessingInstructions[j])+"_"+ (*i)->accesses[j]+"}";
           }
	    else
		{
           temp=temp.substr(0,temp.length()-1);
	   temp=temp+","+std::to_string((*i)->accessingThread[j])+"_"+  std::to_string((*i)->accessingInstructions[j])+"_"+ (*i)->accesses[j]+"}";
 	   }  }  
           execution[l]=temp;
      }
      // std::cout << execution[i] << std::endl;
    }
                    }
                }
            }
        }
    }
  for(int i=0;i<execution.size();i++)
  {
    bt_string=bt_string+execution[i]+" ";
  }
if(first_run)
{
      string st="LAST="+std::to_string(last_ins)+"1";
      char set[100];
      strcpy(set, st.c_str());
      //setenv("LAST", st.c_str(), true);
      putenv(set);
      cout <<"reaching "<< getenv("LAST")<< endl;
      system("export LAST=1");
     // unsetenv("LAST");
             //     if(putenv(set)!=0)
                      //fprintf(stderr,"putenv failed\n");

}
/*if there was only one race to be relayed at race point move up else play the remaining races*/
if(!first_run)
{
  if(!only_race)
  {
        runfrom.open("runfrom.out");
        runfrom << "detail" <<endl;
        runfrom.close();
    for(int t=1;t<prev_exec.size();t++)
    {
      if(t!=race_point)
        detail_s=detail_s+prev_exec[t]+" ";
      if(t == race_point)
        {
	string tmp1=prev_exec[t];
	std::size_t last_c=tmp1.find_last_of(',');
        tmp1=tmp1.substr(0,last_c);
	tmp1=tmp1+"}";
        detail_s=detail_s+tmp1+" ";
         }
      char set_det[80]="RUN_INFO=detail";
      putenv(set_det);
	    /*store the same execution trace without the replayed race*/
	  }
}
    if (only_race)
       { 
        runfrom.open("runfrom.out");
        runfrom << "bt" <<endl;
        runfrom.close();
        detail_s=bt_string;
        char set_var[80]="RUN_INFO=backtrack";
        putenv(set_var);
    //system("echo $RUN_INFO");
      }
    details.open("details.out");
    details << totalThreads <<" "<< detail_s <<endl;
}
  bt.open("backtrack.out");
  cout << "total ins : " << totalins <<endl;
  bt_string=std::to_string(totalThreads)+" "+bt_string;
  bt << bt_string <<endl;
  bt.close();
  details.close();
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
{   state st;
    bool d=false;
    deque<int> dq;  
    int p=0;
    sem_init(&sem, 0, 0);
    sem_init(&dep, 0, 0);
    sem_init(&rev, 0, 0);
    sem_init(&wait_last, 0, 0);
    std::ifstream file0("runfrom.out");
    std::ifstream file1("backtrack.out");
    std::ifstream file2("details.out");
    FILE * pFile2;
    FILE * run_file;
    pFile2 = fopen ( "backtrack.out" , "r" );
    run_file = fopen ( "runfrom.out" , "r" );
    fseek(pFile2, 0, SEEK_END); 
    fseek(run_file, 0, SEEK_END); 
    if(ftell(pFile2) != 0)
    { /*if backtrack is not empty, record the previous execution stack*/
      string sLine,info;
      if(ftell(run_file) != 0)
      {
       std::getline(file0, info);
       cout << info << "is info" << endl;
       if(info.compare("bt")==0)
       d=false;
       if (info.compare("detail")==0) 
       d=true;    
       }
       if(d)
	{
         std::getline(file2, sLine);
	}
        else 
	{
	 std::getline(file1, sLine);
	}
   //   if( std::getline(file1, sLine))
	{
        istringstream iss(sLine);
        do
       {
        string subs;
        iss >> subs;
        if(subs!="")
       { 
	prev_exec.push_back(subs);
	std::size_t f=subs.find_first_of('{');	
        string x=subs.substr(0,f);
        std::size_t u=x.find_first_of('_');
        st.tid=std::stoi(x.substr(0,u));
	x=x.substr(u+1);
	u=x.find_first_of('_');
	st.count=std::stoi(x.substr(0,u));
	cout << st.tid <<" " <<st.count<<endl;
        if(p==0)/*for the first run the order is initialized to 0*/
	{
         for(int r=0;r<st.tid;r++)
	  {
	order.push_back(dq);
		}
	}
	if(p>0){/*for other runs, store into order*/
	        
	   order[st.tid].push_back(st.count);
	  }
	stack.push_back(st);
	p++;
        }
                 } while (iss);
   
       }
   /*   else{
	 cout<<"Error: File has no more lines to read."<<endl;
	 exit (EXIT_FAILURE);
	 }*/
     }
    else
    {
    first_run=true;
     }

    if(!first_run)
     {
     cout <<"before"<<endl;
     const char* env_1 = std::getenv("LAST");
     last0 = atoi (env_1);
     int i;
     for(i=prev_exec.size()-1;i>0;i--)
       {

      if(!((prev_exec[i].at(prev_exec[i].length()-1)=='}')&&(prev_exec[i].at(prev_exec[i].length()-2)=='{')))
	{   /*find the reversible races from the bootom most state*/
        race_point=i;/*set up the index of bottom most race*/
	std::size_t us1,us2;
        target=prev_exec[i];
	std::size_t open=target.find_last_of('{');
	std::size_t first=target.find_first_of('{');
	state1=target.substr(0,first-1);
	std::size_t us=state1.find_first_of('_');
        tid1=std::stoi(state1.substr(0,us));
        string temp1 = state1.substr(us+1);
        std::size_t ls=temp1.find_first_of('_');
        count1=std::stoi(temp1.substr(0,ls));
        string t=target.substr(open+1); 
	state2=t;
	state2=state2.substr(0, state2.length()-1);
	cout<<"state1 "<<state2<<endl;
	if (state2.find(',') != std::string::npos)
	   {
	    std::size_t comma=state2.find_last_of(',');
	    state2=state2.substr(comma+1);
            us1=state2.find_first_of('_');
	    tid2=std::stoi(state2.substr(0,us1));
	    state2=state2.substr(us1+1);
	    us2=state2.find_first_of('_');
	    count2=std::stoi(state2.substr(0,us2));
            only_race=false;
	    }
	else
	    {
            us1=state2.find_first_of('_');
	    tid2=std::stoi(state2.substr(0,us1));
	    state2=state2.substr(us1+1);
	    us2=state2.find_first_of('_');
	    count2=std::stoi(state2.substr(0,us2));    
	    only_race=true;     
	     }
        bool done=false;
	break;
	}
      if(i==0)
	finished=true;
      else
	finished=false;
      }

	}
          thread_count = stack.front().tid;
   for(int ii=0;ii<thread_count;ii++)
     {
      thread_fini.push_back(false);
      sem_init(&semaphores[ii].s, 0, 0);
      }
    if(stack.size()>2){
    stack.pop_front(); 
    curr_state=stack.front();
    stack.pop_front();
    next_state=stack.front(); 
}
 

    load_read_write_sets();
    sharedAccesses.open("sharedAccesses.out");
    races.open("races.out");
    allLocks.reserve(20);

    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    

   // pinplay_engine.Activate(argc, argv,
     // KnobPinPlayLogger, KnobPinPlayReplayer);
    
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
