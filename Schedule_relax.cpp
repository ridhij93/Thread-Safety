#include "definitions.h"
#include "Dyn.h"
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
#include <sched.h>
#include <sys/time.h>
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <thread>
#include <errno.h>
#include <semaphore.h>
#include <chrono>
#include <thread> 
#include <sched.h>
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

KNOB<BOOL> KnobPinPlayLogger(KNOB_MODE_WRITEONCE,
                      "pintool", "log", "0",
                      "Activate the pinplay logger");

KNOB<BOOL> KnobPinPlayReplayer(KNOB_MODE_WRITEONCE,
                      "pintool", "replay", "0",
                      "Activate the pinplay replayer");
int tid_s, tid_l, count_s, count_l;
int tid_match=0;
string ins_current;
Dyn d;
int ins_match=0;
INS sched_ins;
int line;
   ifstream infile;
ifstream infile_table;
int present=0;
//AFUNPTR ori_funptr;

sem_t m;
//AFUNPTR ori_funptr_;

int var2, var5;
string ins_s,ins_l;
UINT32 var1,var3,var4,var6;
PIN_THREAD_UID scheduler_thd_uid_; 

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


VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v){
//int policy;
struct sched_param param2;
sched_getparam(0,&param2);

cout << "Thread id and priority " << threadid <<" " <<param2.sched_priority<< endl;  

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



VOID incrementThreadINS(THREADID tid, INS ins){
    ThreadLocalData *tld = getTLS(tid);
    tld->insCount++;
   // cout <<tid<<" "<<tld->insCount <<endl;
  if((tid==tid_s)&&(tld->insCount==count_s))
   {tid_match=1;
//cout <<"tid_match \n";
}

  if((ins_match==1)&&(tid_match==1))
      {
       present=1;
       ins_match=0; 
         tid_match=0;
      d.interleave();
       cout << "*******************************************************************\n";
      }
   
//cout << tld->insCount<<" "<<tid<<endl;

  //tld->thread_trace << INS_Disassemble(ins).c_str() << endl;
}



void rec_mem(INS ins, THREADID tid){
    ins_current=INS_Disassemble(ins);
    if((ins_current==ins_s))
    {  
      ins_match=1;
   // cout<<"match " <<ins_current << " "<<tld->insCount<<" "<<tid<<endl;
    }
   INS_InsertCall(ins, 
                   IPOINT_BEFORE,
                   (AFUNPTR) incrementThreadINS, 
                   IARG_THREAD_ID,
                   IARG_PTR, ins,
                   IARG_END);
       if(ins_current==ins_l)
     {
     INS_Delete(ins);
 // cout <<"deleted"<<endl;
     }
 }



VOID Trace(TRACE trace, VOID *val)
{
 if (!filter.SelectTrace(trace))
        return;
top=race_ins1.front();
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {



  // if (!IMG_IsMainExecutable(img))
    //   return;    

  THREADID tid=PIN_ThreadId();
  rec_mem(ins,tid);

present=0;
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

void preprocess()
 {
    int index=0;
    int old_pos=0;
    int new_pos=0; 
    string items[6];
    string str,str2;
    string s=" $$$ ";
    infile.open ("instruction.txt");
    infile_table.open ("table.txt");
 //   for(int i = 0; i < line; ++i)/*Needs to check if n has not crossed the total number of linrs in infile*/
  //	{
	 if( std::getline(infile, str)){
          std::getline(infile_table, str2);
          //cout <<str<<endl;
          }
	 else
	{
	cout<<"Error: File has no more lines to read."<<endl;
	exit (EXIT_FAILURE);
	}
 //    }
    for (int j=0; j<str2.length(); ++j)
    {
        if(str2[j]==' ')
         {
          new_pos=j;
          index++;
            if(index==1)
              tid_s=atoi((str2.substr(old_pos, new_pos-old_pos)).c_str());
            if(index==4)
              tid_l=atoi(str2.substr(old_pos, new_pos-old_pos).c_str());
            if(index==2)
              count_s=atoi(str2.substr(old_pos, new_pos-old_pos).c_str());
            if(index==5)
             count_l=atoi(str2.substr(old_pos, new_pos-old_pos).c_str());
//cout<< (str2.substr(old_pos, new_pos-old_pos))<<endl;
          } 
         old_pos=new_pos+1;
   // cout<< old_pos<<" "<<new_pos<<" "<< index<<endl;
    }
 //cout << tid_s <<" "<<tid_l<<" "<<count_s<<" "<<count_l<<endl;
    std::size_t found = str.find(s);
    std::string str3 = str.substr(found+5);
    ins_l=str3;
    ins_s=str.substr(0,found); 
   // cout <<ins_s <<endl;
}

int main(int argc, char * argv[])
{

//line=2;
  
sem_init(&m, 0, 0);
    allLocks.reserve(20);

const char* env_1 = std::getenv("line");
line = atoi (env_1);
preprocess();

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
