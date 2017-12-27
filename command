
server copy
 sudo scp -r ~/Documents/Project/ pmachine@192.168.1.156:/home/pmachine/Intel_PIN/pin/source/tools/ridhi


compile cpp file with mutex:

g++ -std=c++11 -pthread file_name.cpp 


../../../../../pin -t obj-intel64/thread_rw.so -- /home/pmachine/Intel_PIN/pin/source/tools/ridhi/Project/code/locks


make obj-intel64/thread_set.so

export PIN_ROOT=/home/pmachine/Intel_PIN/pin/

cd Intel_PIN/pin/source/tools/ridhi/Project/code/

 sudo scp pmachine@192.168.1.156:/home/pmachine/Intel_PIN/pin/source/tools/ridhi/Project/code/rwrite.out /home/ridhi/Downloads/pin-3.0-76991-gcc-linux/source/tools/ManualExamp

 ssh pmachine@192.168.1.156

valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./test

compiler: g++ sample.cpp -o sample -ldl -lpthread

program:  gcc -c -fPIC sample.cpp -o sample.o
	gcc threads.o -shared -o threads.so -lpthread


sudo scp /home/ridhi/Downloads/pin-3.0-76991-gcc-linux/source/tools/ManualExamples/filter.cpp pmachine@192.168.1.156:/home/pmachine/Intel_PIN/pin/source/tools/ridhi/Project/code/

sudo scp /home/ridhi/Desktop/Stacks1.cpp pmachine@192.168.1.156:/home/pmachine/Intel_PIN/pin/source/tools/ridhi/Project/code/


protoc -I=/home/ridhi/Documents/thread/pinplay-drdebug-2.2-pldi2015-pin-2.14-71313-gcc.4.4.7-linux/extras/pinplay/examples/ --cpp_out=/home/ridhi/Documents/thread/pinplay-drdebug-2.2-pldi2015-pin-2.14-71313-gcc.4.4.7-linux/extras/pinplay/examples /home/ridhi/Documents/thread/pinplay-drdebug-2.2-pldi2015-pin-2.14-71313-gcc.4.4.7-linux/extras/pinplay/examples/static_info.proto 



to collect test drivers:

sudo apt-get install autoconf
sudo apt-get install libtools
./autogen.sh
./configure
make -f Makefile

callgraph:
$ clang++ -S -emit-llvm main1.cpp -o - | opt -analyze -dot-callgraph
$ dot -Tpng -ocallgraph.png callgraph.dot




 -filter_no_shared_libs


export PROTOBUF_HOME=/usr/local/


../../../../../pin -appdebug_enable -t obj-intel64/stackdebug.so -stackbreak 400 -- /home/pmachine/Intel_PIN/pin/source/tools/ridhi/Project/code/threads1


 ../../../../../pin -appdebug -t obj-intel64/stackdebug.so -stackbreak 100 -- /home/pmachine/Intel_PIN/pin/source/tools/ridhi/Project/code/threads1

$PIN_ROOT/pin -t obj-intel64/ReadWriteSets.so -filter_no_shared_libs -log -log:basename pinball/foo -- /home/ridhi/Downloads/pin-3.0-76991-gcc-linux/source/tools/ManualExamples/threadx

 $PIN_ROOT/pin -xyzzy -reserve_memory pinball/foo.address -t obj-intel64/LockUnlock.so -filter_no_shared_libs -replay -replay:basename pinball/foo -- $PIN_ROOT/extras/pinplay/bin/intel64/nullapp >> cxyzw

$PIN_ROOT/pin -t obj-intel64/Scheduler1.so -filter_no_shared_libs -- /home/ridhi/Downloads/pin-3.0-76991-gcc-linux/source/tools/ManualExamples/threadx

Intel credentials:
ridhij@iiitd.ac.in
ridhi#123

sudo apt-get install --reinstall g++

 sudo scp /home/ridhi/Downloads/sai.jpg dhritik@iiitd.edu.in@www.iiitd.edu.in:/mnt/Storage/www/pag/sites/default/files/images/students

