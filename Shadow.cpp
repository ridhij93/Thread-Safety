/*trace the prev details: if done is found after any race remove that done and replay races */
#include "Control.h"
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
#include <ctime>
#define window_size 1
//PINPLAY_ENGINE pinplay_engine;
//KNOB<BOOL> KnobPinPlayLogger(KNOB_MODE_WRITEONCE,
//                    "pintool", "log", "0",
//                  "Activate the pinplay logger");

//KNOB<BOOL> KnobPinPlayReplayer(KNOB_MODE_WRITEONCE,
//                    "pintool", "replay", "0",
//                  "Activate the pinplay replayer");

// Contains knobs to filter out things to instrument
FILTER filter;
ofstream instructions;
int start_s, stop_s;
CONTEXT *ctxtx = new CONTEXT;
state break_point;
bool done = false;
bool wait_at_break[2] = {false, false};
bool reached_breakpoint = false;
int total = 0;
int total1 = 0;
string second;
bool pre_executed = false;
int last_ins = 0;
bool not_wait = false;
string ins_l;
bool next_execute = false;
string ins_s;
int next_tid, next_count;
deque<relax_info> relax_ds;
vector<pair<THREADID, vector<relax_element>>> relax_struct;
bool all = false;
ofstream endrun;
bool race = true;
bool wait_t1 = false;
bool post_t2 = false;
int race_point = 0;
bool only = false;
string detail_s = "";
string s = "";
bool stack_end = false;
int thread_count;
int tid1, tid2, count1, count2, relax_tid2, relax_count2;
string relax_ins2;
string target = "";
string state1, state2;
vector<Lock*> allLocks;
list<MemoryAddr*> memSet;
bool first_run = false;
int totalThreads = 0;
int totalins = 0;
PIN_LOCK GlobalLock;
TLS_KEY tls_key;
string bt_string = "";
set<ADDRINT> writeIntersection;
string event;
map<THREADID, THREADID> mapOfThreadIDs;
//ofstream sharedAccesses;
ofstream races;
ofstream relax_detail;
ofstream bt;
string relax_s = "";
vector<string> prev_exec;
vector<string> enabled;
vector<string> execution;
struct sema
{
    sem_t s;
    int wait = 0;
};


//deque<sema> semaphores;
sema semaphores[100];
vector<deque<int>> order;


state curr_state, next_state;
deque<state> stack;
bool executed = false;
bool waited = false;
template <class T>
inline void PRINT_ELEMENTS (const T& coll, ThreadLocalData *tld, const char* optcstr = "")
{
    typename T::const_iterator pos;

    tld->out << optcstr;
    for (pos = coll.begin(); pos != coll.end(); ++pos) {
        tld->out << *pos << ' ';
    }
    tld->out << std::endl;
}

template <class T>
inline void PRINT_ELEMENTS_OUTPUT (const T& coll, const char* optcstr = "")
{
    typename T::const_iterator pos;

    cout << "PIN: " << optcstr;
    for (pos = coll.begin(); pos != coll.end(); ++pos) {
        cout << *pos << ' ';
    }
    cout << std::endl;
}

void updateMemoryClocks(ThreadLocalData* tld, Lock* lock) {
    set<ADDRINT>::const_iterator pos;

    for (pos = lock->memReadAccesses.begin(); pos != lock->memReadAccesses.end(); ++pos) {
        list<MemoryAddr*>::const_iterator lookup =
            find_if(memSet.begin(), memSet.end(), mem_has_addr(*pos));
        if (lookup != memSet.end()) {
            int j;
            int size = (*lookup)->accessingInstructions.size();
            for (j = 0; j < size; j++) {
                if (((*lookup)->accessingInstructions[j] > lock->lock_inst)
                        && ((*lookup)->accessingInstructions[j] < lock->unlock_inst)
                        && (tld->threadId == (*lookup)->accessingThread[j])) {
                    (*lookup)->accessClocks[j].receiveActionFromSpecialPoint(tld->currentVectorClock, tld->threadId);
                }
            }
        }

    }

    for (pos = lock->memWriteAccesses.begin(); pos != lock->memWriteAccesses.end(); ++pos) {
        list<MemoryAddr*>::const_iterator lookup =
            find_if(memSet.begin(), memSet.end(), mem_has_addr(*pos));
        if (lookup != memSet.end()) {
            int j;
            int size = (*lookup)->accessingInstructions.size();
            for (j = 0; j < size; j++) {
                if (((*lookup)->accessingInstructions[j] > lock->lock_inst)
                        && ((*lookup)->accessingInstructions[j] < lock->unlock_inst)
                        && (tld->threadId == (*lookup)->accessingThread[j])) {
                    (*lookup)->accessClocks[j].receiveActionFromSpecialPoint(tld->currentVectorClock, tld->threadId);
                }
            }
        }

    }

}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    cout << "PIN: Thread Start:" << threadid << endl;
    vector<relax_element> re;
    relax_element e;
    re.push_back(e);
    sema sema_t;
    //semaphores.push_back(sema_t);
    relax_struct.push_back(make_pair(threadid, re));

    ThreadLocalData* tld = new ThreadLocalData(threadid);
    sem_init(&semaphores[threadid].s, 0, 0);
    if (threadid == 0) {
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
        for (unsigned int i = 1; getline(read, line); ++i)
            tld->readSet.insert(atoll(line.c_str()));

        stringstream writeSet;
        writeSet << "writeSet" << threadid << ".out";
        ifstream write(writeSet.str().c_str());
        for (unsigned int i = 1; getline(write, line); ++i)
            tld->writeSet.insert(atoll(line.c_str()));

        PIN_SetThreadData(tls_key, tld, threadid);
        PIN_GetLock(&GlobalLock, threadid);
        ++totalThreads;
        PIN_ReleaseLock(&GlobalLock);
    }
    else {
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
        for (unsigned int i = 1; getline(read, line); ++i)
            tld->readSet.insert(atoll(line.c_str()));

        stringstream writeSet;
        writeSet << "writeSet" << threadid << ".out";
        ifstream write(writeSet.str().c_str());
        for (unsigned int i = 1; getline(write, line); ++i)
            tld->writeSet.insert(atoll(line.c_str()));

        PIN_SetThreadData(tls_key, tld, threadid);
        PIN_GetLock(&GlobalLock, threadid);
        ++totalThreads;
        PIN_ReleaseLock(&GlobalLock);
    }
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    all = true;
    ThreadLocalData* tld = getTLS(threadid);
    tld->out.close();
    //if (threadid == 0)
    //  last_ins = tld->insCount;
    if (threadid != 0) {
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
    cout << "PIN: Thread Finished:" << threadid << " " << semaphores[0].wait << semaphores[1].wait << semaphores[2].wait << endl;
    free(tld);
    PIN_SetThreadData(tls_key, 0, threadid);
}

VOID CheckCMPXCHG(THREADID threadid, INS ins) {
    ThreadLocalData* tld = getTLS(threadid);
    if (INS_Opcode(ins) == CMPXCHG) {
        tld->isCMPXCHG = 1;
    }
}

VOID CheckEAX(THREADID threadid, ADDRINT value, REG _reg, INS ins) {
    PIN_LockClient();
    ThreadLocalData* tld = getTLS(threadid);
    if (REG_FullRegName(_reg) == EAX_REG && value == 0) {
        tld->isEAXZero = 1;
    }
    if (REG_FullRegName(_reg) == EAX_REG && value == 2) {
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
            if (lookup == allLocks.end())
                found = false;
            else
                found = (*lookup)->isLocked;
            PIN_ReleaseLock(&GlobalLock);

            if (value == 0 && !found) {
                tld->isZeroBefore = 1;
            }
            else if (value == 1 && !found) {
                tld->isOneBeforeAndUnlocked = 1;
            }

            else if (value == 1 && found) {
                tld->isOneBeforeAndLocked = 1;
            }
            else if (value == 2 && found)
                tld->isTwoBefore = 1;
        }
    }
    PIN_UnlockClient();
}

VOID RecordMemoryWriteAfterINS(THREADID threadid, INS ins) {
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
            if (lookup == allLocks.end())
                found = false;
            else
                found = (*lookup)->isLocked;
            PIN_ReleaseLock(&GlobalLock);

            if (value == 0 && found) {
                lockMemoryWrite = memoryWrite;
                tld->isZeroAfter = 1;
            }
            if (value == 1 && !found) {
                lockMemoryWrite = memoryWrite;
                tld->isOneAfterAndUnlocked = 1;
            }
            if (value == 1 && found) {
                lockMemoryWrite = memoryWrite;
                tld->isOneAfterAndLocked = 1;
            }
            if (value == 2 && !found) {
                lockMemoryWrite = memoryWrite;
                tld->isTwoAfter = 1;
            }
        }
    }

    int zeroOneLock = tld->isEAXZero && tld->isZeroBefore && tld->isOneAfterAndUnlocked;
    int zeroTwoLock = tld->isEAXTwo && tld->isZeroBefore && tld->isTwoAfter;

    if (zeroOneLock || zeroTwoLock) {
        PIN_GetLock(&GlobalLock, tld->threadId);
        tld->out << "Lock Detected" << endl;
        tld->out << INS_Disassemble(ins) << endl;
        tld->currentVectorClock->event();
        tld->out << lockMemoryWrite->effective_address << endl;
        set<ADDRINT>::iterator it = writeIntersection.find(lockMemoryWrite->effective_address);
        if (it != writeIntersection.end())
            writeIntersection.erase(it);
        vector<Lock*>::const_iterator lookup =
            find_if(allLocks.begin(), allLocks.end(), lock_has_addr(lockMemoryWrite->effective_address));
        if (lookup == allLocks.end()) {
            Lock *l = new Lock(lockMemoryWrite->effective_address);
            l->lock_it(tld->insCount);
            allLocks.push_back(l);
            l->lockVectorClock->receiveAction(tld->currentVectorClock);
            tld->acqLocks.push_back(l);
        }
        else {
            (*lookup)->lock_it(tld->insCount);
            (*lookup)->lockVectorClock->receiveAction(tld->currentVectorClock);
            tld->acqLocks.push_back((*lookup));
        }
        PIN_ReleaseLock(&GlobalLock);
    }

    int zeroOneUnlock = tld->isOneBeforeAndLocked && tld->isZeroAfter;
    int twoOneUnlock = tld->isTwoBefore && tld->isOneAfterAndLocked;
    int twoZeroUnlock = tld->isTwoBefore && tld->isZeroAfter;

    if (zeroOneUnlock || twoOneUnlock || twoZeroUnlock) {
        PIN_GetLock(&GlobalLock, tld->threadId);
        tld->out << "Unlocked" << endl;
        tld->currentVectorClock->event();
        tld->out << INS_Disassemble(ins) << endl;
        tld->out << lockMemoryWrite->effective_address << endl;

        vector<Lock*>::const_iterator lookup =
            find_if(allLocks.begin(), allLocks.end(), lock_has_addr(lockMemoryWrite->effective_address));
        if (lookup != allLocks.end()) {
            (*lookup)->unlock_it(tld->insCount);
            (*lookup)->lockVectorClock->receiveAction(tld->currentVectorClock);

            for (unsigned i = 0; i < (*lookup)->recordClocks.size(); ++i) {
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
                if ((!out1.empty()) || (!out2.empty()) || (!out3.empty())) {
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
            if (acqLock != tld->acqLocks.end())
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


VOID incrementThreadINS(THREADID tid, ADDRINT ins_addr, INS ins, CONTEXT *ctxt, int size) {
    ThreadLocalData *tld = getTLS(tid);
    tld->insCount++;
    cout  << "PIN: " << tid << " " << tld->insCount << " " << stack_end << endl;
    if (!first_run && !race ) {
        for (std::deque<state>::iterator si = stack.begin(); si != stack.end(); ++si)
        {
            if ((si->tid == tid) && (si->count == tld->insCount))
            {
                if (si->done && si->pro)
                {
                    if (semaphores[tid].wait < 1)
                    {
                        semaphores[tid].wait++;
                        sem_wait(&semaphores[tid].s);
                    }
                }
            }
        }
    }
    /*Release locks on all threads if executed successfull till last inversion*/
    if (!first_run)
    {
        if ((((next_state.tid == 0) && (next_state.count == 0)) || ((stack_end) && (done)) ) || ((curr_state.tid == 0) && (curr_state.count == 0)))
        {
            for (int k = 0; k < thread_count; k++)
            {
                if (!((race) && (k == tid1) && (!post_t2)))
                {
                    if (semaphores[k].wait > 0)
                    {
                        cout << "PIN: in release " << k << endl;
                        semaphores[k].wait--;
                        sem_post(&semaphores[k].s);
                    }
                }
            }
        }
        /* close if(!first_run)*/
        if ((stack_end) && (!done) && (tid != tid2) && (tld->insCount >= order[tid].front()) && (!race))
        {
            cout << "PIN: Other Wait " << tid << endl;
            if (semaphores[tid].wait < 1)
            {
                semaphores[tid].wait++;
                sem_wait(&semaphores[tid].s);
            }
        }

	/**/
        if (stack_end)
        {
            bool dependent = false;
            if ((race) && (tid != tid2) && (!done) && ((tld->insCount >= order[tid].front()) || ((tld->insCount == count1) && (tid == tid1))))
            {
                cout << "PIN: WAIT " << tid << tld->insCount << " " << order[tid].front() << endl;
                for (int i = 0; i < stack.size(); i++) {
                    if ((stack[i].tid == tid) && (stack[i].tid != tid1) && (stack[i].count == tld->insCount))
                    {
                        dependent = true;
                        break;
                    }
                    if ((stack[i].tid == tid2) && (stack[i].count == count2))
                        break;
                }
                if (!dependent)
                {
                    if (semaphores[tid].wait < 1)
                    {
                        semaphores[tid].wait++;
                        sem_wait(&semaphores[tid].s);
                    }
                }
            }
            if ((race) && (tid == tid2) && (tld->insCount > count2) && (!done))
            {
                cout << "PIN: POST" << endl;
                done = true;
                for (int i = 0; i < thread_count; i++)
                {
                    if (semaphores[i].wait > 0)
                    {
                        semaphores[i].wait--;
                        sem_post(&semaphores[i].s);
                    }
                }
            }
        }
    ADDRINT TakenIP = (ADDRINT)PIN_GetContextReg( ctxt, REG_INST_PTR );
        std::deque<relax_info>::iterator it = relax_ds.begin();
        {
            if ((tid == it->tid1) && (tld->insCount == it->count1) && (!it->done) && (!it->executed1))
            {
                cout << "PIN: ***************************   DELETE1   **********************"  << stack.front().tid << " " << stack.front().count << endl;
                for (std::deque<state>::iterator si = stack.begin(); si != stack.end(); ++si)
                {
                    if ((si->tid == tid) && (si->count == tld->insCount))
                        si->done = true;
                    if ((stack.front().count != it->count1) && (stack.front().tid != stack[1].tid))
                    {
                        si->pro = true;
                    }
                    //stack_end = true;
                }
                if (tld->insCount >= order[tid].front())
                {
                    order[tid].pop_front();
                    cout << "PIN: popping1" << endl;
                }


                //PIN_SetContextReg(ctxt, REG_INST_PTR, (ADDRINT)(TakenIP));
                //it->ctxt1 = ctxt;
                PIN_SaveContext (ctxt, it->ctxt1);
                //PIN_SetContextReg(it->ctxt1, REG_INST_PTR, (ADDRINT)(TakenIP));
                //cout << "PIN: Context 1" << it->ctxt1 << endl;
                //PIN_SetContextReg(it->ctxt1, REG_INST_PTR, (ADDRINT)(ctxt));
                //PIN_SetContextReg(ctxt, REG_INST_PTR, (ADDRINT)(TakenIP + size));
                PIN_SetContextReg(ctxtx, REG_INST_PTR, (ADDRINT)(TakenIP + size));
                it->executed1 = true;
                PIN_ExecuteAt(ctxtx);
            }
            if ((tid == it->tid2) && (tld->insCount == it->count2 + 1) && (it->executed1) && (!it->done) && (!it->executed2))
            {
                cout << "PIN: ***************************   INSERT1   ********************** " << stack.front().tid << " " << stack.front().count <<  endl;
                for (std::deque<state>::iterator si = stack.begin(); si != stack.end(); ++si)
                {
                    if ((si->tid == tid) && (si->count == it->count2))
                    {
                        si->done = true;
                    }
                }
                if (tld->insCount >= order[tid].front())
                {order[tid].pop_front(); cout << "PIN: popping " << tid << " " << order[tid].front() << endl;}
                //PIN_SetContextReg(ctxtx, REG_INST_PTR, addr1);
                //it->ctxt2 = ctxt;
                it->saved = TakenIP;
                PIN_SetContextReg(it->ctxt2, REG_INST_PTR, (ADDRINT)(TakenIP + size));
                //PIN_SaveContext (ctxt, it->ctxt2);
                it->executed2 = true;
                tld->insCount = it->count1 - 1;
                PIN_ExecuteAt(it->ctxt1);
            }
            /*  if ((tid == it->tid2) && (tld->insCount == it->count2 + 3) && (it->executed1) && (it->executed2) && (!it->done))
              {
                it->done = true;
            stack_end = true;
            cout << "PIN: ***************************   POST1   **********************" << endl;
            done = true;
            for(int i = 0; i < thread_count; i++)
               {
                if (semaphores[i].wait > 0)
                       {
                       semaphores[i].wait--;
                       sem_post(&semaphores[i].s);
                       }
               }

                //tld->insCount = tld->insCount - 3;
                //PIN_SetContextReg(it->ctxt2, REG_INST_PTR, (ADDRINT)(TakenIP + size));
            //PIN_SetContextReg(ctxtx, REG_INST_PTR, addr2);
                //PIN_ExecuteAt(it->ctxt2);
                }*/

        }
        if (!first_run) {
            for (std::deque<relax_info>::iterator it = relax_ds.begin(); it != relax_ds.end(); ++it)
            {
                if (it !=  relax_ds.begin()) {
                    //cout <<  "UNSEEEEEEEEEEE " << it->tid1 << " " << it->count1 << " " << it->count2 << endl;
                    if ((tid == it->tid1) && (tld->insCount == it->count1) && (!it->done) && (!it->executed1))
                    {
                        //ADDRINT TakenIP = (ADDRINT)PIN_GetContextReg( ctxt, REG_INST_PTR );
                        cout << "PIN: **** DELETE ********" << stack.front().tid << " " << stack.front().count << " " << tid << it->count1 << endl;

                        for (std::deque<state>::iterator si = stack.begin(); si != stack.end(); ++si)
                        {
                            if ((si->tid == tid) && (si->count == tld->insCount))
                            {
                                si->done = true;
                                if ((stack.front().count != it->count1) && (stack.front().tid != stack[1].tid))
                                {
                                    si->pro = true;
                                }
                            }
                            // if ((tid == tid1) && (tld->insCount=count1) && (!race))
                            //   stack_end = true;
                            if ((curr_state.tid == tid) && (curr_state.count == tld->insCount))
                            {
                                curr_state = next_state;
                                stack.pop_front();
                                next_state = stack.front();
                                order[tid].pop_front();
                                executed = waited;
                                waited = false;
                            }
                            if ((next_state.tid == tid) && (next_state.count == tld->insCount))
                            {
                                stack.pop_front();
                                next_state = stack.front();
                                order[tid].pop_front();
                                waited = false;
                            }
                        }
                        if (tld->insCount >= order[tid].front())
                        {
                            order[tid].pop_front();
                            cout << "PIN: popping1" << endl;
                        }
                        PIN_SaveContext (ctxt, it->ctxt1);
                        //PIN_SetContextReg(it->ctxt1, REG_INST_PTR, (ADDRINT)(ctxt));
                        PIN_SetContextReg(ctxtx, REG_INST_PTR, (ADDRINT)(TakenIP + size));
                        it->executed1 = true;
                        PIN_ExecuteAt(ctxtx);
                    }
                    if ((tid == it->tid2) && (tld->insCount == it->count2 + 1) && (it->executed1) && (!it->done) && (!it->executed2))
                    {
                        cout << "PIN: ***** INSERT **********" << stack.front().tid << " " << stack.front().count  << " " << tid << it->count2 << tld->insCount << endl;
                        it->saved = TakenIP;
                        for (std::deque<state>::iterator si = stack.begin(); si != stack.end(); ++si)
                        {
                            if ((si->tid == tid) && (si->count == it->count2))
                            {
                                si->done = true;
                            }
                            if ((curr_state.tid == tid) && (curr_state.count == it->count2))
                            {
                                curr_state = next_state;
                                stack.pop_front();
                                next_state = stack.front();
                                order[tid].pop_front();
                                executed = waited;
                                waited = false;
                            }
                            if ((next_state.tid == tid) && (next_state.count == it->count2))
                            {
                                stack.pop_front();
                                next_state = stack.front();
                                order[tid].pop_front();
                                waited = false;
                            }

                        }
                        if (tld->insCount >= order[tid].front())
                        {order[tid].pop_front(); cout << "PIN: popping2" << endl;}
                        it->ctxt2 = ctxt;
                        it->executed2 = true;
                        tld->insCount = it->count1 - 1;
                        PIN_ExecuteAt(it->ctxt1);
                    }
                    /*  if ((tid == it->tid2) && (tld->insCount == it->count2 + 2) && (it->executed1) && (it->executed2) && (!it->done))
                      {
                        cout << "PIN: ***************************   EVEN   **********************" << endl;
                        cout << it->tid1 << tid1 << it->tid2 << tid2 << it->count1 << count1 << it->count2 << count2 << endl;
                        it->done = true;
                        PIN_ExecuteAt(it->ctxt2);
                        tld->insCount--;
                        }*/
                }
            }
        }

        if ((!stack_end))
        {
            if ((curr_state.tid == next_state.tid))
            {
                PIN_LockClient();
                while ((curr_state.tid == next_state.tid))
                {
                    if (stack.size() >= 1)
                    {
                        //cout << "PIN: same threads: changing to next" << endl;
                        curr_state = next_state;
                        stack.pop_front();
                        order[curr_state.tid].pop_front();
                        next_state = stack.front();
                    }
                    else
                    {
                        stack_end = true;
                        break;
                    }
                }
                PIN_UnlockClient();
            }


            while ((curr_state.done) || (next_state.done))
            {
                cout << "*****************SWITCHING*********************" << endl;
                PIN_LockClient();
                if (curr_state.done)
                {
                    curr_state = next_state;
                    stack.pop_front();
                    next_state = stack.front();
                    order[curr_state.tid].pop_front();
                }
                if (next_state.done)
                {
                    if (stack.size() > 1)
                    {
                        stack.pop_front();
                        next_state = stack.front();
                        order[next_state.tid].pop_front();
                    }
                    else
                    {
                        waited = true;
                        stack_end = true;
                        executed = true;
                        next_execute = true;
                        curr_state.tid = 0;
                        next_state.tid = 0;
                        curr_state.count = 0;
                        next_state.count = 0;
                        break;
                    }
                }
                PIN_UnlockClient();
            }
            while ((order[curr_state.tid].front() < curr_state.count) && (order[curr_state.tid].size() > 0) && (order[curr_state.tid].front() > 0))
            {
                cout << "PIN: popping 1" << order[curr_state.tid].front() << " " << curr_state.count << endl;
                order[curr_state.tid].pop_front();  /*Pop for same threads*/
                cout << "PIN: Current top " << order[curr_state.tid].front() << endl;
            }
            while ((order[next_state.tid].front() < next_state.count) && (order[next_state.tid].size() > 0) && (order[next_state.tid].front() > 0))
            {
                cout << "PIN: popping 2" << order[next_state.tid].front() << " " << next_state.count << endl;
                order[next_state.tid].pop_front(); /*Pop for same threads*/
                cout << "PIN: Next top " << order[next_state.tid].front() << endl;
            }
            if ((pre_executed) && (curr_state.tid == tid))
            {
                executed = true;
                pre_executed = false;
                if (semaphores[next_state.tid].wait > 0)
                {
                    semaphores[next_state.tid].wait--;
                    sem_post(&semaphores[next_state.tid].s);
                    cout << "PIN: **************** POSTING****************" << endl;
                }
            }
            if ((((tld->insCount >= order[tid].front()) && (curr_state.tid == tid) && (curr_state.count <= tld->insCount))) && (!executed))
            {
                cout << "PIN: front of current state " << order[tid].front() << " " << tid << " " << curr_state.count << " " << next_state.tid << " " << next_state.count << endl;
                cout << "PIN: current tid " << tid << endl;
                pre_executed = true;
                order[tid].pop_front();
                sched_yield();
                cout << "PIN: top of order's current state " << order[tid].front() << " " << tid << " " << curr_state.count << " " << semaphores[0].wait << semaphores[1].wait << semaphores[2].wait << endl;

            }
            if ((tid == next_state.tid) && (tld->insCount >= order[next_state.tid].front()) && (!waited) && (order[next_state.tid].front() != 0))
            {
                cout << "PIN: current pair " << curr_state.tid << " " << curr_state.count << " " << next_state.tid << " " << next_state.count << endl;
                cout << "PIN: waiting for next state " << tid << " " << tld->insCount << endl;
                waited = true;
                order[tid].pop_front();
                cout << "PIN: order after waiting for next state " << tid << " " << order[tid].front() << endl;
                string curr = std::to_string(curr_state.tid) + "_" + std::to_string(curr_state.count) + "_" + "r_{" + std::to_string(curr_state.tid) + "}_{" + std::to_string(curr_state.tid) + "}_[]_{}";

                if ((!executed) && ((std::find(execution.begin(), execution.end(), curr) == execution.end())))
                {
                    if (semaphores[curr_state.tid].wait > 0)
                    {
                        cout << "PIN: I am posting " << curr_state.tid << endl;
                        semaphores[curr_state.tid].wait--;
                        sem_post(&semaphores[curr_state.tid].s);
                    }
                    //sched_yield();
                    cout << "PIN: I am waiting " << tid << " " << tld->insCount << endl;
                    if (semaphores[tid].wait < 1)
                    {
                        semaphores[tid].wait++;
                        sem_wait(&semaphores[tid].s);
                    }
                }
            }
            if (((tid == curr_state.tid) || (tid == next_state.tid)) && (tld->insCount >= order[tid].front()) && (order[tid].front() != 0))
            {
                if ((tid == next_state.tid) && (tld->insCount > next_state.count))
                {
                    next_execute = true; // set true if the next state has already executed
                }
                cout << "PIN: Same thread waiting " << tid << " " << tld->insCount << " " << order[tid].front() << endl;
                next_tid = stack[1].tid; // assign the next active state *Check*
                next_count = stack[1].count;
                cout << "PIN: Same thread waiting post " << tid << " " << tld->insCount << " " << order[tid].front() << endl;
                if (((tid == next_state.tid) || (tid == curr_state.tid)) && (tld->insCount == order[tid].front()) && (tid == next_tid) && (tld->insCount == next_count) && (waited && executed))
                {
                    waited = false;
                    executed = false;
                    next_execute = false;
                    curr_state = next_state;
                    if (stack.size() <= 1)
                    {
                        stack_end = true;
                    }
                    stack.pop_front();
                    stack.pop_front();
                    curr_state = stack.front();
                    stack.pop_front();
                    next_state = stack.front();
                    order[tid].pop_front();
                    cout << "PIN: Next State same: Will not wait" << tid << " " << tld->insCount << " " << curr_state.tid << " " << curr_state.count << " " << next_state.tid << " " << next_state.count << endl;
                    not_wait = true;
                }
                if (!executed)
                {
                    if (semaphores[curr_state.tid].wait > 0)
                    {
                        semaphores[curr_state.tid].wait--;
                        sem_post(&semaphores[curr_state.tid].s);
                    }
                }

                if ((semaphores[tid].wait < 1) && (!not_wait))
                {
                    cout << "PIN: Same thread waiting :WAITS" << tid << " " << tld->insCount << endl;
                    semaphores[tid].wait++;
                    sem_wait(&semaphores[tid].s);
                }
                not_wait = false;
            }
            if ((tid != curr_state.tid) && (tid != next_state.tid) && (order[tid].front() > 0) && (tld->insCount >= order[tid].front() ))
            {
                cout << "PIN: other thread waiting for next state " << tid << " " << tld->insCount << " " << curr_state.tid << " " << next_state.tid << " " << semaphores[curr_state.tid].wait << semaphores[next_state.tid].wait << endl;
                if (!executed)
                {
                    if (semaphores[curr_state.tid].wait > 0)
                    {
                        semaphores[curr_state.tid].wait--;
                        sem_post(&semaphores[curr_state.tid].s);
                    }
                }
                //sched_yield();
                if (semaphores[tid].wait < 1)
                {
                    semaphores[tid].wait++;
                    sem_wait(&semaphores[tid].s);
                }

            }
            if ((tid == next_state.tid) && (tld->insCount > next_state.count))
            {
                next_execute = true;
            }
            if (waited && executed && next_execute)
            {
                next_execute = false;
                curr_state = next_state;
                if (stack.size() <= 1)
                {
                    if (wait_t1 && post_t2)
                        stack_end = true;
                }
                stack.pop_front();
                next_state = stack.front();
                curr_state = next_state;
                stack.pop_front();
                next_state = stack.front();
                cout << "PIN: state changing " << curr_state.tid << " " << next_state.tid << endl;
                waited = false;
                executed = false;
                cout << "PIN: " << curr_state.tid << " this is the new next state" << curr_state.count << endl;
                while (semaphores[curr_state.tid].wait > 0)
                {
                    cout << "PIN: " << curr_state.tid << " Releasing locks on next state " << curr_state.count  << endl;
                    semaphores[curr_state.tid].wait--;
                    sem_post(&semaphores[curr_state.tid].s);
                }
                //sched_yield();
            }//    if(waited && executed)
        }  // if((!reverse_point)&&(!stack_end))
    }    //if((!first_run)&&(!finished)&&(!stack_end))

}
VOID MemoryReadInst(THREADID threadid, ADDRINT effective_address, int i )
{

    relax_element read_element;
    list<MemoryAddr*>::const_iterator lookup1 =
        find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if (lookup1 == memSet.end())
    {
        MemoryAddr* mem = new MemoryAddr(effective_address);
        memSet.push_back(mem);
        writeIntersection.insert(effective_address);
    }
    list<MemoryAddr*>::const_iterator lookup =
        find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if (lookup != memSet.end()) {
        ThreadLocalData* tld = getTLS(threadid);
        PIN_GetLock(&GlobalLock, tld->threadId);
        cout << "PIN: Read " << threadid << " " << tld->insCount << " " << effective_address << endl;
        //sharedAccesses << tld->threadId << " " << tld->insCount << " r " << effective_address << "," << endl;
        PIN_ReleaseLock(&GlobalLock);
        tld->addAddressToLockRead(effective_address);
        tld->currentVectorClock->event();
        PIN_GetLock(&((*lookup)->MemoryLock), tld->threadId);
        (*lookup)->operand_index.push_back(i);
        (*lookup)->accesses.push_back('r');
        (*lookup)->accessingThread.push_back(threadid);
        (*lookup)->accessingInstructions.push_back(tld->insCount);
        (*lookup)->accessClocks.push_back(*(tld->currentVectorClock));
        int size = (*lookup)->accesses.size();
        if ((threadid == break_point.tid) && (tld->insCount == break_point.count))
        {
            stack_end = true;
        }
        for (int k = 0; k < size - 1; k++) {
            if ((*lookup)->accesses[k] == 'w') {
                if ((*lookup)->accessClocks[k].areConcurrent(&((*lookup)->accessClocks[size - 1]))) {
                    instructions << "race " << (*lookup)->accessingThread[k] << " " << (*lookup)->accessingInstructions[k] << " " << (*lookup)->accessingThread[size - 1] << " " << (*lookup)->accessingInstructions[size - 1] << endl;
                }
            }
        }
        event = std::to_string(threadid) + "_" + std::to_string(tld->insCount) + "_" + "r_{" + std::to_string(threadid) + "}_{" + std::to_string(threadid) + "}_[]_{}";
        execution.push_back(event);
        read_element.tid = threadid;
        read_element.vc = tld->currentVectorClock;
        read_element.ins = ins_l;
        read_element.addr = effective_address;
        read_element.i_count = tld->insCount;
        read_element.type = 'r';
        for (std::vector<pair<THREADID, vector<relax_element>>>::iterator it = relax_struct.begin(); it != relax_struct.end(); ++it)
        {
            if (it->first == threadid)
            {
                int size = it->second.size();
                for (int k = size - 1; k >= size - window_size; k--)
                {
                    if ((it->second[k].type == 'w')  && (effective_address != it->second[k].addr))
                        instructions << "relax " << it->second[k].tid << " " << it->second[k].i_count << " " << threadid << " " << tld->insCount << endl;
                    else
                        break;
                }
                it->second.push_back(read_element);
            }
        }
        for (std::deque<relax_info>::iterator it = relax_ds.begin(); it != relax_ds.end(); ++it)
        {
            if ((it->executed1) && (it->executed2) && (it->done) && (threadid == it->tid1) && (tld->insCount == it->count1))
            {
                tld->insCount = it->count2;
            }
        }
        PIN_ReleaseLock(&((*lookup)->MemoryLock));
    }

}

VOID MemoryWriteInst(THREADID threadid, ADDRINT effective_address, int i) {

    relax_element write_element;
    list<MemoryAddr*>::const_iterator lookup1 =
        find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if (lookup1 == memSet.end())
    {
        MemoryAddr* mem = new MemoryAddr(effective_address);
        memSet.push_back(mem);
        writeIntersection.insert(effective_address);
    }
    list<MemoryAddr*>::const_iterator lookup =
        find_if(memSet.begin(), memSet.end(), mem_has_addr(effective_address));
    if (lookup != memSet.end()) {
        ThreadLocalData* tld = getTLS(threadid);
        PIN_GetLock(&GlobalLock, tld->threadId);
        //sharedAccesses << tld->threadId << " " << tld->insCount << " w " << effective_address << "," << endl;
        cout << "PIN: write " << threadid << " " << tld->insCount  << " " << effective_address << endl;
        PIN_ReleaseLock(&GlobalLock);
        tld->addAddressToLockWrite(effective_address);
        tld->currentVectorClock->event();
        PIN_GetLock(&((*lookup)->MemoryLock), tld->threadId);
        (*lookup)->accesses.push_back('w');
        (*lookup)->operand_index.push_back(i);
        (*lookup)->accessingThread.push_back(threadid);
        (*lookup)->accessingInstructions.push_back(tld->insCount);
        (*lookup)->accessClocks.push_back(*(tld->currentVectorClock));
        int size = (*lookup)->accesses.size();
        if ((threadid == break_point.tid) && (tld->insCount == break_point.count))
        {
            stack_end = true;
        }
        for (int k = 0; k < size - 1; k++) {
            if ((*lookup)->accessClocks[k].areConcurrent(&((*lookup)->accessClocks[size - 1]))) {
                instructions << "race " << (*lookup)->accessingThread[k] << " " << (*lookup)->accessingInstructions[k] << " " << (*lookup)->accessingThread[size - 1] << " " <<   (*lookup)->accessingInstructions[size - 1] << endl;
            }
        }
        event = std::to_string(threadid) + "_" + std::to_string(tld->insCount) + "_" + "w_{" + std::to_string(threadid) + "}_{" + std::to_string(threadid) + "}_[]_{}";
        execution.push_back(event);
        write_element.tid = threadid;
        write_element.vc = tld->currentVectorClock;
        write_element.ins = ins_s;
        write_element.addr = effective_address;
        write_element.i_count = tld->insCount;
        write_element.type = 'w';
        for (std::vector<pair<THREADID, vector<relax_element>>>::iterator it = relax_struct.begin(); it != relax_struct.end(); ++it) {
            if (it->first == threadid)
            {
                int size = it->second.size();
                for (int k = size - 1; k >= size - window_size; k--)
                {
                    if ((it->second[k].type == 'w')  && (effective_address != it->second[k].addr))
                        instructions << "relax " << it->second[k].tid << " " << it->second[k].i_count << " " << threadid << " " << tld->insCount << endl;
                    else
                        break;
                }
                it->second.push_back(write_element);
            }
        }
        for (std::deque<relax_info>::iterator it = relax_ds.begin(); it != relax_ds.end(); ++it)
        {
            if ((it->executed1) && (it->executed2) && (it->done) && (threadid == it->tid1) && (tld->insCount == it->count1))
            {
                tld->insCount = it->count2;
            }
        }
        PIN_ReleaseLock(&((*lookup)->MemoryLock));
    }

}

void __BreakPoint(THREADID tid)
{

    ThreadLocalData *tld = getTLS(tid);
//cout << "PIN: In Breakpoint " << tid << " " << tld->insCount <<" "<< tid1<<" "<<count1 << " " <<tid2 <<" "<< count2 << endl;
    if ((tid == break_point.tid) && (tld->insCount == break_point.count))
    {
        cout << "PIN: BREAKPOINT" << endl;
        reached_breakpoint = true;
    }
    if ((tid == tid2) && (tld->insCount == count2 - 1))
    {
        for (std::deque<state>::iterator si = stack.begin(); si != stack.end(); ++si)
        {
            if ((si->tid == tid) && (si->count == tld->insCount))
                if (! si->done)
                {
                    cout << "PIN: BREAKPOINT WAIT 2 " << tid2 << endl;
                    if (!reached_breakpoint)
                    {
                        if (semaphores[tid2].wait < 1)
                        {
                            wait_at_break[1] = true;
                            semaphores[tid2].wait++;
                            sem_wait(&semaphores[tid2].s);
                        }
                    }
                }
        }
    }
    if ((tid == tid1) && (tld->insCount == count1) && (!first_run))
    {
        for (std::deque<state>::iterator si = stack.begin(); si != stack.end(); ++si)
        {
            if ((si->tid == tid) && (si->count == tld->insCount))
                if (! si->done)
                {
                    cout << "PIN: BREAKPOINT WAIT 1 " << tid1 << endl;
                    if (!reached_breakpoint)
                    {
                        if (semaphores[tid1].wait < 1)
                        {
                            wait_at_break[0] = true;
                            semaphores[tid1].wait++;
                            sem_wait(&semaphores[tid1].s);
                        }
                    }
                }
        }
    }
    if ((reached_breakpoint) && (wait_at_break[0]) && ((done && race) || (!race)))
    {
        cout << "PIN: BREAKPOINT POST " << tid << endl;
        if (semaphores[tid1].wait > 0)
        {
            semaphores[tid1].wait--;
            sem_post(&semaphores[tid1].s);
        }
        //reached_breakpoint = false;
        wait_at_break[0] = false;
    }
    if ((reached_breakpoint) && (wait_at_break[1]))
    {
        cout << "PIN: BREAKPOINT POST " << tid << endl;
        if (semaphores[tid2].wait > 0)
        {
            semaphores[tid2].wait--;
            sem_post(&semaphores[tid2].s);
        }
        //reached_breakpoint = false;
        wait_at_break[1] = false;
    }
}

void rec_mem(INS ins) {

    THREADID tid = PIN_ThreadId();
    ThreadLocalData *tld = getTLS(tid);
    int sz = INS_Size(ins);
    tld->insCount2++;
    //cout  << tid << " " << tld->insCount<< " " << INS_Disassemble(ins) << " " << endl;

    INS_InsertCall(ins,
                   IPOINT_BEFORE,
                   (AFUNPTR) __BreakPoint,
                   IARG_THREAD_ID,
                   IARG_END);


    INS_InsertCall(ins,
                   IPOINT_BEFORE,
                   (AFUNPTR) incrementThreadINS,
                   IARG_THREAD_ID,
                   IARG_ADDRINT, INS_Address(ins),
                   IARG_PTR, ins,
                   IARG_CONTEXT,
                   IARG_UINT32, sz,
                   IARG_END);



    std::deque<relax_info>::iterator it = relax_ds.begin();
    if ((it->executed1) && (it->executed2) && (!it->done) && (tid == it->tid1))
    {
        cout << "PIN: ***************************   EVEN1   ********************** " << INS_Disassemble(ins) << endl;
        it->done = true;
        stack_end = true;
        if (!race)
            done = true;
        for (int i = 0; i < thread_count; i++)
        {
            if ((semaphores[i].wait > 0) && (!race))
            {
                semaphores[i].wait--;
                sem_post(&semaphores[i].s);
            }
        }
	if (race)
	{
	    if (semaphores[tid].wait > 0)
            {
                semaphores[tid].wait--;
                sem_post(&semaphores[tid].s);
		order[tid].pop_front();
            }
	    }
        //tld->insCount = it->count2;
        it->done = true;
        INS_InsertDirectJump(ins, IPOINT_AFTER, it->saved);
        // INS_Delete(INS_Next(ins));
    }
    for (std::deque<relax_info>::iterator it = relax_ds.begin(); it != relax_ds.end(); ++it)
    {
        if (it !=  relax_ds.begin())
        {
	//cout << it->tid1 <<" "<< it->count1 << " " << it->executed1 <<it->executed2 <<it->done<<" "<<tid <<it->tid1<< endl; 
            if ((it->executed1) && (it->executed2) && (!it->done) && (tid == it->tid1))
            {
                cout << "PIN: ***************************   EVEN   ********************** " << INS_Disassemble(ins) << endl;
                it->done = true;
                //tld->insCount = it->count2;
                //tld->insCount = tld->insCount - 2;
                INS_InsertDirectJump(ins, IPOINT_AFTER, it->saved);
            }
        }
    }
    if ((INS_IsStackRead(ins)) || (INS_IsStackWrite(ins)))
        return;
    UINT32 num_operands = INS_MemoryOperandCount(ins);
    UINT32 i;
    for (i = 0; i < num_operands; ++i) {
        if (INS_MemoryOperandIsRead(ins, i)) {
            ins_l = INS_Disassemble(ins);

            INS_InsertCall(ins,
                           IPOINT_BEFORE,
                           (AFUNPTR) MemoryReadInst,
                           IARG_THREAD_ID,
                           IARG_MEMORYOP_EA, i,
                           IARG_UINT32, i,
                           IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, i)) {

            ins_s = INS_Disassemble(ins);
            INS_InsertCall(ins,
                           IPOINT_BEFORE,
                           (AFUNPTR) MemoryWriteInst,
                           IARG_THREAD_ID,
                           IARG_MEMORYOP_EA, i,
                           IARG_UINT32, i,
                           IARG_END);
        }
    }

}

VOID Trace(TRACE trace, VOID *val)
{

    string img_name = "";
    //if ((!IMG_IsMainExecutable(img)))
    // return;
    PIN_GetLock(&GlobalLock, -1);
    ThreadLocalData *tld = getTLS(mapOfThreadIDs[PIN_GetTid()]);
    PIN_ReleaseLock(&GlobalLock);
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            SEC sec;
            IMG img;
            RTN rtn;
            rtn = INS_Rtn(ins);
            if (RTN_Valid(rtn))
            {
                sec = RTN_Sec(rtn);
                img = SEC_Img(sec);
            }
            else
                return;
            if (IMG_Valid (img))
                img_name = IMG_Name(img);
            if ((!filter.SelectTrace(trace)) && (img_name.find("bzip") == std::string::npos))
                return;

            if (INS_IsAtomicUpdate(ins)) {

                check_lock(ins);
            }
            rec_mem(ins);
            tld->thread_trace << INS_Disassemble(ins) << endl;

        }
    }
}
VOID Fini(INT32 code, void *v)
{
    string temp = "";
    string instruction2 = std::to_string(tid2) + "_" + std::to_string(count2);
    list<MemoryAddr *>::const_iterator i;
    for (i = memSet.begin(); i != memSet.end(); i++) {
        cout << "PIN: **********************************" << endl;
        cout << "PIN: " << (*i)->addr << endl;

        int size = (*i)->accesses.size();
        int k;
        for (k = 0; k < size; k++) {
            cout << "PIN: " << k << ": " << endl;
            cout << "PIN: " << (*i)->accessingThread[k] << endl;
            cout << "PIN: " << (*i)->accessingInstructions[k] << endl;
            cout << "PIN: " << (*i)->accesses[k] << endl;

            int j;
            cout << "PIN: " ;
            for (j = 0; j < totalThreads; j++) {
                cout <<  (*i)->accessClocks[k].vclock_arr[j] << " ";
            }
            cout << endl;
        }

    }
    while (execution.size() > enabled.size())
    {
        enabled.push_back("");
    }
    for (i = memSet.begin(); i != memSet.end(); i++) {
        int size = (*i)->accesses.size();
        int k;
        for (k = 0; k < size; k++) {
            int j;
            for (j = k + 1; j < size; j++) {
                if (j == k)
                    continue;
                if ((*i)->accesses[k] == 'w' || (*i)->accesses[j] == 'w') {
                    if ((*i)->accessClocks[k].areConcurrent(&((*i)->accessClocks[j]))) {
                        //  races << "**********************************" << endl;
                        //races << (*i)->addr << endl;
                        //races << "Race Detected" << endl;
                        races << (*i)->accessingThread[k] <<
                              " " << (*i)->accessingInstructions[k] <<
                              " " << (*i)->accesses[k] << " " /*<< (*i)->operand_index[k] << " " */ << (*i)->accessingThread[j] <<
                              " " << (*i)->accessingInstructions[j] <<
                              " " << (*i)->accesses[j] << /*" " << (*i)->operand_index[j] <<*/ endl;
                        s = std::to_string((*i)->accessingThread[k]) + "_" +  std::to_string((*i)->accessingInstructions[k]) + "_" + (*i)->accesses[k];

                        for ( int l = 0 ; l < execution.size(); l++ )
                        {

                            if ((l == race_point - 1) && (race) && (enabled[l].find(second) != std::string::npos))
                            {
                                if (only)
                                    enabled[l] = enabled[l].substr(0, enabled[l].find(second)) + "}";
                                else
                                    enabled[l] = enabled[l].substr(0, enabled[l].find(second) - 1) + "}";
                            }

                            if (l >= race_point - 1)
                                temp = execution[l];
                            else
                                temp = prev_exec[l + 1];

                            size_t brk = temp.find_first_of('{');
                            string temp2 = temp.substr(0, brk - 1);
                            std::size_t index = execution[l].find(s); /*if you find a race, search for instruction in execution*/
                            if ((index != std::string::npos) && (index < execution[l].find_first_of('{')))
                            {
                                total++;
                                if ((execution[l].find(instruction2) != std::string::npos) && ((execution[l].find(instruction2) < execution[l].find_first_of('{'))) && (race))
                                {
                                    if (((*i)->accessingThread[j] == tid1) && ((*i)->accessingInstructions[j] == count1))
                                        continue;
                                }
                                if ((first_run) || (l >= race_point - 1))
                                {
                                    if ((temp.at(temp.length() - 2) == '{') && (temp.at(temp.length() - 1) == '}'))
                                    {
                                        temp = temp.substr(0, temp.length() - 1);
                                        temp = temp + std::to_string((*i)->accessingThread[j]) + "_" +  std::to_string((*i)->accessingInstructions[j]) + "_" + (*i)->accesses[j] + "}";
                                    }
                                    else
                                    {
                                        temp = temp.substr(0, temp.length() - 1);
                                        temp = temp + "," + std::to_string((*i)->accessingThread[j]) + "_" +  std::to_string((*i)->accessingInstructions[j]) + "_" + (*i)->accesses[j] + "}";
                                    }

                                }
                            }
                            execution[l] = temp;
                            if ((!first_run) && (l >= race_point))
                            {
                                enabled[l] = temp;
                            }
                        }
                    }
                }
            }
        }
    }

    for (int i = 0; i < totalThreads; i++)
    {

        for (int k = relax_struct[i].second.size() - 1; k > 0; k--)
        {

            for (int l = k - 1; (l >= k - window_size) && (l >= 0); l--)
            {
                for (int m = 0; m < execution.size(); m++)
                {
                    if ((m == race_point - 1) && (!race) && (enabled[m].find(second) != std::string::npos))
                    {
                        if (only)
                            enabled[m] = enabled[m].substr(0, enabled[m].find(second)) + enabled[m].substr(enabled[m].find_last_of(']'));
                        else
                            enabled[m] = enabled[m].substr(0, enabled[m].find(second) - 1) + enabled[m].substr(enabled[m].find_last_of(']'));
                        enabled[m] = enabled[m].substr(0, enabled[m].find_first_of('}') + 1) + "_#" + std::to_string(relax_ds.front().tid2) + " " + std::to_string(relax_ds.front().count2) + "#" + enabled[m].substr(enabled[m].find_first_of('}') + 1);
                    }

                    if ((relax_struct[i].second[l].type == 'w') && ((k - l) <= window_size) && (relax_struct[i].second[l].addr != relax_struct[i].second[k].addr))
                    {
                        string local, sub1, sub2;
                        string prev_ins = std::to_string(relax_struct[i].second[l].tid) + "_" + std::to_string(relax_struct[i].second[l].i_count) + "_";
                        string next_ins = std::to_string(relax_struct[i].second[k].tid) + "_" + std::to_string(relax_struct[i].second[k].i_count) + "_" + relax_struct[i].second[k].ins;
                        std::size_t index = execution[m].find(prev_ins); /*if you find a race, search for instruction in execution*/
                        if ((index != std::string::npos) && (index < execution[m].find_first_of('{')))
                        {
                            local = execution[m];
                            std::size_t last_sq = local.find_last_of(']');
                            if ((execution[m].find(instruction2) != std::string::npos) && ((execution[m].find(instruction2) < execution[m].find_first_of('{'))) && (!race))
                            {
                                if ((relax_struct[i].second[k].tid == tid1) && (relax_struct[i].second[k].i_count == count1))
                                    continue;
                            }
                            if ((m >= race_point - 1) || (first_run))
                            {
                                if (next_ins.find("mov") != std::string::npos)
                                {
                                    total1++;
                                    if ((local.at(last_sq - 1) == '['))
                                    {
                                        sub1 = local.substr(0, last_sq);
                                        sub2 = local.substr(last_sq);
                                        local = sub1 + next_ins + sub2;
                                    }
                                    else
                                    {
                                        sub1 = local.substr(0, last_sq);
                                        sub2 = local.substr(last_sq);
                                        local = sub1 + "." + next_ins + sub2;
                                    }
                                    execution[m] = local;
                                }
                            }
                            else
                                execution[m] = prev_exec[m + 1];
                        }

                        if ((!first_run) && (m >= race_point))
                            enabled[m] = execution[m];

                    }
                }
                if (relax_struct[i].second[l].addr == relax_struct[i].second[k].addr)
                    break;
            }
        }
    }

    for (int i = 0; i < execution.size(); i++)
    {
        string id = "*";
        if ((i == race_point - 1) && (enabled[i].find("explore") == std::string::npos))
            id = "*explore";
        if (!first_run)
            bt_string = bt_string + id + enabled[i] + "\n";
        else
            bt_string = bt_string + id + execution[i] + "\n";
        bt_string = bt_string + execution[i] + "\n";
    }
    instructions.close();
    bt.open("backtrack.out");
    cout << "PIN: total ins : " << totalins << endl;
    bt_string = std::to_string(totalThreads) + "\n" + bt_string;
    bt << bt_string  << /*prev_exec[prev_exec.size() - 1] << "\n" <<*/ endl;
    bt.close();
    //details.close();
    stop_s = clock();
    cout << "PIN: time: " << (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000 << endl;
    cout << "PIN: total race: " << total << endl;
    cout << "PIN: total relax: " << total1 << endl;
}

INT32 Usage()
{
    cerr <<
         "PIN: This pin tool tries to find the locks and unlocks in a program.\n"
         "\n";

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

void load_read_write_sets() {
    string line;
    ifstream writeins("writeSetIntersection.out");
    for (unsigned int i = 1; getline(writeins, line); ++i) {
        writeIntersection.insert(atoll(line.c_str()));
        MemoryAddr* mem = new MemoryAddr(atoll(line.c_str()));
        memSet.push_back(mem);
    }
}

int main(int argc, char * argv[])
{

    state st;
    deque<int> dq = {};
    relax_info ri;
    int p = 0;
    instructions.open("instructions.out");
    std::ifstream file1("backtrack.out");
    FILE * pFile2;
    FILE * run_file;
    pFile2 = fopen ( "backtrack.out" , "r" );
    fseek(pFile2, 0, SEEK_END);
    if (ftell(pFile2) != 0)
    {   /*if backtrack is not empty, record the previous execution stack*/
        string subs;
        while (std::getline(file1, subs))
        {
            if ((subs != "") && (subs.at(0) != '*'))
            {
                prev_exec.push_back(subs);
                std::size_t f = subs.find_first_of('{');
                string x = subs.substr(0, f);
                std::size_t u = x.find_first_of('_');
                st.tid = std::stoi(x.substr(0, u));
                x = x.substr(u + 1);
                u = x.find_first_of('_');
                st.count = std::stoi(x.substr(0, u));
                cout << "PIN: " << st.tid << " " << st.count << endl;
                if (p == 0) /*for the first run the order is initialized to 0*/
                {
                    for (int r = 0; r < st.tid; r++)
                    {
                        order.push_back(dq);
                    }
                }
                if (p > 0)
                {   /*for other runs, store into order*/
                    if ((order[st.tid].size() > 0) && (order[st.tid][order[st.tid].size() - 1] < st.count))
                        order[st.tid].push_back(st.count);
                    if (order[st.tid].size() == 0)
                        order[st.tid].push_back(st.count);
                }
                stack.push_back(st);
                p++;
            }
            else if ((subs != "") && (subs.at(0) == '*'))
            {
                enabled.push_back(subs.substr(1));
            }
        }
    }
    else
    {
        first_run = true;
    }

    if (!first_run)
    {
        for (int i = enabled.size(); i > 0; i--)
        {
            if ((enabled[i - 1].at(enabled[i - 1].length() - 2) == '{') && (enabled[i - 1].find_last_of(']') - enabled[i - 1].find_first_of('[') == 1)  )
            {
                if (prev_exec[i].at(prev_exec[i].length() - 2) != '{')
                    prev_exec[i] = prev_exec[i].substr(0, prev_exec[i].find_last_of('{') + 1) + "}";
                if (prev_exec[i].at(prev_exec[i].find_last_of(']') - 1) != '[')
                    prev_exec[i] = prev_exec[i].substr(0, prev_exec[i].find_first_of('[') + 1) + prev_exec[i].substr(prev_exec[i].find_last_of(']'));
            }
            if (enabled[i - 1].find("explore") != std::string::npos)
                enabled[i - 1] =  enabled[i - 1].substr(7);
            std::size_t h2 = enabled[i - 1].find_last_of('#');
            std::size_t h1 = enabled[i - 1].find_first_of('#');
            if (enabled[i - 1].find("#") != std::string::npos)
            {
                enabled[i - 1] = enabled[i - 1].substr(0, h1 - 1) + enabled[i - 1].substr(h2 + 1);
            }
            target = enabled[i - 1];
            std::size_t sb2 = target.find_last_of(']');
            std::size_t sb1 = target.find_first_of('[');
            std::size_t us1, us2;
            std::size_t open = target.find_last_of('{');
            std::size_t first = target.find_first_of('{');
            state1 = target.substr(0, first - 1);
            std::size_t us = state1.find_first_of('_');
            tid1 = std::stoi(state1.substr(0, us));
            string temp1 = state1.substr(us + 1);
            std::size_t ls = temp1.find_first_of('_');
            count1 = std::stoi(temp1.substr(0, ls));
            if (enabled[i - 1].at(sb2 - 1) != '[')
            {
                race_point = i;
                race = false;
                state2 = target.substr(sb1 + 1, sb2 - sb1 - 1);
                if (state2.find('.') != std::string::npos)
                {
                    std::size_t dot = state2.find_last_of('.');
                    state2 = state2.substr(dot + 1);
                    second = state2;
                    us1 = state2.find_first_of('_');
                    relax_tid2 = std::stoi(state2.substr(0, us1));
                    state2 = state2.substr(us1 + 1);
                    us2 = state2.find_first_of('_');
                    relax_count2 = std::stoi(state2.substr(0, us2));
                    relax_ins2 = state2.substr(us2 + 1);
                    relax_ins2 = relax_ins2.substr(0, relax_ins2.length() - 1);
                    only = false;
                }
                else
                {
                    second = state2;
                    us1 = state2.find_first_of('_');
                    relax_tid2 = std::stoi(state2.substr(0, us1));
                    state2 = state2.substr(us1 + 1);
                    us2 = state2.find_first_of('_');
                    relax_count2 = std::stoi(state2.substr(0, us2));
                    relax_ins2 = state2.substr(us2 + 1);
                    relax_ins2 = relax_ins2.substr(0, relax_ins2.length() - 1);
                    cout << "PIN: single" << tid1 << relax_tid2 << relax_count2 << count1 << endl;
                    only = true;
                }
                cout << "PIN: Pushin back" << second  << " " << enabled[race_point - 1] << " " << race << endl;
                tid2 = relax_tid2;
                count2 = relax_count2;
                ri.tid1 = tid1;
                ri.tid2 = relax_tid2;
                ri.count1 = count1;
                ri.count2 = relax_count2;
                ri.ins = relax_ins2;
                relax_ds.push_back(ri);
                relax_detail.open("relaxdetail.out");
                relax_detail << state1 << " " << relax_tid2 << " " << relax_count2 << " $$$" << relax_ins2 << endl;
                relax_detail.close();
                break;
            }
            if (!((enabled[i - 1].at(enabled[i - 1].length() - 1) == '}') && (enabled[i - 1].at(enabled[i - 1].length() - 2) == '{')))
            {
                /*find the reversible races from the bootom most state*/
                race_point = i; /*set up the index of bottom most race*/
                string t = target.substr(open + 1);
                state2 = t;
                state2 = state2.substr(0, state2.length() - 1);
                cout << "PIN: state1 " << state2 << endl;
                if (state2.find(',') != std::string::npos)
                {
                    std::size_t comma = state2.find_last_of(',');
                    state2 = state2.substr(comma + 1);
                    second = state2;
                    us1 = state2.find_first_of('_');
                    tid2 = std::stoi(state2.substr(0, us1));
                    state2 = state2.substr(us1 + 1);
                    us2 = state2.find_first_of('_');
                    count2 = std::stoi(state2.substr(0, us2));
                    only = false;
                }
                else
                {
                    second = state2;
                    us1 = state2.find_first_of('_');
                    tid2 = std::stoi(state2.substr(0, us1));
                    state2 = state2.substr(us1 + 1);
                    us2 = state2.find_first_of('_');
                    count2 = std::stoi(state2.substr(0, us2));
                    only = true;
                }
                break;
            }

            thread_count = std::stoi(prev_exec[0]);
        }

        if (race_point <= 0)
        {
            endrun.open("endrun.out");
            endrun << "true" << endl;
            endrun.close();
        }
        else
        {
            break_point.tid = stack[race_point - 1].tid;
            break_point.count = stack[race_point - 1].count;
            endrun.open("endrun.out");
            endrun << "race"  << endl;
            endrun.close();
        }
    }
    if (race)
    {
        if ((break_point.tid == tid1) && (break_point.count > count1))
            break_point.count = count1;
        if ((break_point.tid == tid2) && (break_point.count > count2))
            break_point.count = count2;
    }
    if (!race)
    {
        if ((break_point.tid == tid1) && (break_point.count > count1))
            break_point.count = count1;
    }
    cout << "PIN: " << tid1 << " " << count1 << " " << tid2 << " " << count2 << " " << break_point.tid << " " << break_point.count << endl;
    for (int i = 0; i < race_point - 1; i++)
    {

        if ((enabled[i].find("explore") != std::string::npos) && (enabled[i].find("#") != std::string::npos))
        {
            cout << "PIN: here " << enabled[i] << endl;
            string t = enabled[i].substr(7, enabled[i].find_first_of('{') - 10);
            ri.tid1 = std::stoi(t.substr(0, t.find_first_of('_')));
            ri. count1 = std::stoi(t.substr(t.find_first_of('_') + 1));
            t = enabled[i].substr(enabled[i].find_first_of('#') + 1, enabled[i].find_last_of('#') - enabled[i].find_first_of('#') );
            ri.tid2 = std::stoi(t.substr(0, t.find_first_of(' ')));
            ri.count2 = std::stoi(t.substr(t.find_first_of(' ') + 1));
            relax_ds.push_back(ri);
        }
    }
    cout << "PIN:  start " << race_point << endl;
    stack.pop_front();
    if (stack.size() > 2) {
        curr_state = stack.front();
        stack.pop_front();
        next_state = stack.front();
    }

    //load_read_write_sets();
    // sharedAccesses.open("sharedAccesses.out");
    races.open("races.out");
    allLocks.reserve(20);

    PIN_InitSymbols();
    if ( PIN_Init(argc, argv) )
    {
        return Usage();
    }

    // pinplay_engine.Activate(argc, argv,
    // KnobPinPlayLogger, KnobPinPlayReplayer);
    start_s = clock();
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
