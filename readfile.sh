#word1="aa"
count=0
input="/home/ridhi/Documents/thread/pinplay-15/extras/pinplay/examples/races.out"
while IFS= read -r line
do
	for word in $line; do
        Q=`expr $count % 6` 

if [ $Q -eq 0 ]
then
export v0="$word"
elif [ $Q -eq 1 ]
then
export v1="$word"
elif [ $Q -eq 2 ]
then
export v2="$word"
elif [ $Q -eq 3 ]
then
export v3="$word"
elif [ $Q -eq 4 ]
then
export v4="$word"
elif [ $Q -eq 5 ]
then
export v5="$word"
fi
   
count=`expr $count + 1`
done
$PIN_ROOT/pin -t obj-intel64/Scheduler1.so -filter_no_shared_libs -- /home/ridhi/Downloads/pin-3.0-76991-gcc-linux/source/tools/ManualExamples/threadx
echo "$v0 $v1 $v3 $v4 "
echo "aaaaaa"
done < "$input"
#./readfile.sh
