#include "definitions.h"
#include "ThreadLocalData.h"
#include "Lock.h"
#include "pinplay.H"
#include "RaceData.h"
#include "MemoryAddr.h"
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <semaphore.h>
#include <chrono>
#include <thread> 
#include <time.h>
#include "string"
#include <sys/resource.h>
#include <sched.h>
#define MAX_PRIORITY 5
#define MID_PRIORITY 4
#define MIN_PRIORITY 2
#define MIN_PRIORITY2 1
#define CALL_ORIGINAL_PARAM NULL
#define CALL_ORDER_BEFORE IARG_CALL_ORDER, (PINPLAY_ENGINE::PinPlayFirstBeforeCallOrder() - 1)
#define noop (void)0
PINPLAY_ENGINE pinplay_engine;
//pthread_mutex_t mutex;
int sched_inst=0;
bool yield=false;
int done=0;
int last=0;
bool read_op=false;
int success=0;
int sched_thread_id=-1;
INS sched_ins;
AFUNPTR ori_funptr;
RTN rtn;
sem_t m;
AFUNPTR ori_funptr_;
int  rtn_ins=0;
int  rtn_count=0;
CONTEXT *ctxt;
ADDRINT change=0;
int var2, var5;
UINT32 var1,var3,var4,var6;
PIN_THREAD_UID scheduler_thd_uid_; 
//sem_t semaphore;
/*KNOB<BOOL> KnobPinPlayLogger(KNOB_MODE_WRITEONCE,
                      "pintool", "log", "0",
                      "Activate the pinplay logger");

KNOB<BOOL> KnobPinPlayReplayer(KNOB_MODE_WRITEONCE,
                      "pintool", "replay", "0",
                      "Activate the pinplay replayer");*/

// Contains knobs to filter out things to instrument
FILTER filter;

vector<Lock*> allLocks;
list<MemoryAddr*> memSet;

int totalThreads = 0;
int totalins = 0;
PIN_LOCK GlobalLock;
TLS_KEY tls_key;
std::mutex mtx;
set<ADDRINT> writeIntersection;

map<THREADID, THREADID> mapOfThreadIDs;
map<RaceData, RaceData> rm;

//std::queue<map<RaceData, RaceData>> racemap;
RaceData rd1,rd2,top,top2;;
ofstream sharedAccesses;
ofstream races1;
int save_ctxt=0;
bool exit_ctxt=false; 
std::deque<RaceData> race_ins1;
std::deque<RaceData> race_ins2;
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


/*long get_usecs (void)
{
   struct timeval t;
   gettimeofday(&t,NULL);
   return t.tv_sec*1000000+t.tv_usec;
}*/


VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v){
	cout << "Thread Start:" << threadid << endl;
    ThreadLocalData* tld = new ThreadLocalData(threadid);


   struct sched_param param2;
if((int)threadid==0)
{
 param2.sched_priority =MIN_PRIORITY2;
//sched_setparam(0,&param2);
sched_setscheduler(0, SCHED_FIFO, &param2);
}else{
 param2.sched_priority =MID_PRIORITY;
//sched_setparam(0,&param2);
sched_setscheduler(0, SCHED_FIFO, &param2);
}

//sched_yield();
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


/*void CallOriginal(CONTEXT* ctxt_, THREADID tid_) {                                                    
   // assert(ori_funptr_);                                               
    PIN_CallApplicationFunction(                                            
        ctxt_,                                                              
        tid_,                                                               
        CALLINGSTD_DEFAULT,                                                 
        ori_funptr_,   
        PIN_PARG_END()); 
}*/
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v){
//int policy;
struct sched_param param2;
sched_getparam(0,&param2);

cout << "Thread id and priority " << threadid <<" " <<param2.sched_priority<< endl;  

  ThreadLocalData* tld = getTLS(threadid);
	tld->out.close();
    if(threadid!=0){
        THREADID parentThreadId = 0;
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



VOID incrementThreadINS(THREADID tid, INS ins){
    ThreadLocalData *tld = getTLS(tid);
    tld->insCount++;
    if(((int)tld->insCount==var2)&&(PIN_ThreadId()==var1))
     {
	/*sched_inst=1;
	struct sched_param param2;
	param2.sched_priority =MIN_PRIORITY;
	sched_setparam(0,&param2);*/
	sem_wait(&m);
     }
    if((sched_inst==1)&&(yield==false))
     {
       /* sched_inst=2;
        race_ins1.pop_front(); 
        cout <<"call" <<endl;
	int ret=sched_yield();*/
     }
    if(((int)tld->insCount==var5)&&(PIN_ThreadId()==var4))
     {
	sem_post(&m);
     }
    cout << tid << " " <<  tld->insCount<<endl; 
}

VOID Yield(THREADID threadid, INS ins)
     {  

if(yield==false){
yield=true;
   
    cout << INS_Disassemble(ins) << " " << threadid <<" yield\n";
   int ret=sched_yield();
   
    cout << "ret : " << ret <<endl;
}
}

VOID MemoryReadInst(THREADID threadid, ADDRINT effective_address,INS ins,ADDRINT addr){

}

VOID MemoryWriteInst(THREADID threadid, ADDRINT effective_address,INS ins){
ThreadLocalData* tld = getTLS(threadid);
if(((int)tld->insCount==29)&&(threadid==1))
{cout << "match " <<tld->insCount<<endl;
cout << "Yield " <<INS_Disassemble(ins)<<endl;}
if(((int)tld->insCount==25)&&(threadid==2))
{cout << "match " <<tld->insCount<<endl;
cout << "Yield " <<INS_Disassemble(ins)<<endl;}


}
void save_Ctxt(CONTEXT *ctxt1)
{
//ctxt=ctxt1;

}


void exit_Ctxt(CONTEXT *ctxt1)
{
ctxt=ctxt1;
cout <<"change out "<<change<<endl;
PIN_SetContextReg(ctxt,REG_INST_PTR, change);
cout <<"change ctxt"<<endl;
PIN_ExecuteAt(ctxt);
}

void rec_mem(INS ins, THREADID tid){
//cout << "INS REC: " << tid << " "<<INS_Disassemble(ins) <<endl;
     string routine;
     IMG img = IMG_Invalid();
     RTN rtn = INS_Rtn(ins);
     if (RTN_Valid(rtn)) {
        SEC sec = RTN_Sec(rtn);
        if (SEC_Valid(sec)) 
      {
        img = SEC_Img(sec);
      }
   }



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
                           IARG_PTR, ins,
                           IARG_MEMORYREAD_EA,
                           IARG_END);

        }

        if(INS_MemoryOperandIsWritten(ins, i)){
            INS_InsertCall(ins, 
                           IPOINT_BEFORE,
                           (AFUNPTR) MemoryWriteInst, 
                           IARG_THREAD_ID, 
                           IARG_MEMORYOP_EA, i,
                           IARG_PTR, ins,
                           IARG_END);

        }

}

    }



VOID Trace(TRACE trace, VOID *val)
{

top=race_ins1.front();
for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {

   IMG img = IMG_Invalid();

RTN rtn = INS_Rtn(ins);
    if (RTN_Valid(rtn)) {
      SEC sec = RTN_Sec(rtn);
      if (SEC_Valid(sec)) {
        img = SEC_Img(sec);
}}

if(IMG_Valid(img)){
    string str=IMG_Name(img);


   if (!IMG_IsMainExecutable(img))
       return;    
       THREADID tid=PIN_ThreadId();
          rec_mem(ins,tid);

}
}
}
}

VOID Fini(INT32 code, void *v)
{
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
   
        unsigned int id=0,count=0,pos1=0,pos2=0;
char type=' ';
 std::ifstream file("races.out");
    std::string str;
std::string str_type; 



    while (std::getline(file, str))
{
pos1=str.find(' ');
pos2=str.find_last_of(' ');
id=(unsigned int)atoi((str.substr(0,pos1)).c_str());
str_type=(str.substr(pos2+1));
type=str_type[0];
count=atoi((str.substr(pos1+1,(pos2-pos1-1))).c_str());
rd1.tid=id;
rd1.ins=count;
rd1.type=type;


std::getline(file, str);

pos1=str.find(' ');
pos2=str.find_last_of(' ');
id=atoi((str.substr(0,pos1)).c_str());
str_type=(str.substr(pos2+1));
type=str_type[0];
count=atoi((str.substr(pos1+1,(pos2-pos1-1))).c_str());

rd2.tid=id;
rd2.ins=count;
rd2.type=type;


race_ins1.push_back(rd1);
race_ins2.push_back(rd2);

cout <<"" <<race_ins1.back().tid <<" "<<race_ins1.back().ins << " "<< race_ins1.back().type <<" "<<race_ins2.back().tid << " " << race_ins2.back().ins << " " << race_ins2.back().type << endl;
}

    }
/*race_ins1.pop_front();
race_ins2.pop_front();
race_ins1.pop_front();
race_ins2.pop_front*/
}

int main(int argc, char * argv[])
{
sem_init(&m, 0, 0);
   /* load_read_write_sets();
    sharedAccesses.open("sharedAccesses.out");
    races1.open("races1.out");*/
    allLocks.reserve(20);

const char* env_1 = std::getenv("v0");
var1 = atoi (env_1);
const char* env_2 = std::getenv("v1");
var2 = atoi (env_2);
//const char* env_3 = std::getenv("v2");
//var3 = atoi (env_3);
const char* env_4 = std::getenv("v3");
var4 = atoi (env_4);
const char* env_5 = std::getenv("v4");
var5 = atoi (env_5);
//const char* env_6 = std::getenv("v5");
//var6 = atoi (env_6);

cout << var1 <<" "<< var2 <<" "<< var4 <<" "<<var5<< endl;

    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

cout <<"recurr \n";
    //pinplay_engine.Activate(argc, argv,  KnobPinPlayLogger, KnobPinPlayReplayer);
    
    tls_key = PIN_CreateThreadDataKey(0);
    PIN_InitLock(&GlobalLock);

    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

   // INS_AddInstrumentFunction(Trace, 0);
   TRACE_AddInstrumentFunction(Trace, 0);

  PIN_AddFiniFunction(Fini, 0);
//HandleProgramStart();
  //  filter.Activate();
//long end = get_usecs();
//cout << "start: " << end << endl;
    PIN_StartProgram();



   return 0;
}
