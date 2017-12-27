#include<iostream>
#include<stdio.h>
#include<fstream>
#include <sstream>
#include<stdlib.h>
using namespace std;
int main(int argc, char *argv[]) {
char c;
int count=0;
ofstream out;
string str;
string s=" $$$ ";
std::size_t plus;
std::size_t minus;
bool ref_plus=false;
bool ref_minus=false;
std::size_t mov;
std::size_t first_space;
std::string instrument = "";
ifstream infile;
//int n=atoi(argv[1]);
first_space = str.find(" ");
infile.open ("file_relax.txt");
	//for(int i = 0; i < n; ++i)/*Needs to check if n has not crossed the total number of linrs in infile*/
//	  { 
if( std::getline(infile, str)){}
	else{
	 cout<<"Error: File has no more lines to read."<<endl;
	 exit (EXIT_FAILURE);
	 }
	//
        //std::getline(infile, str);
	out.open("Dyn.cpp");
	std::size_t found = str.find(s);
	std::string str3 = str.substr(found+5);
        std::size_t space1 = str3.find(" ");
        if (space1!=std::string::npos)
        str3=str3.substr(space1+1);
        //cout << str3 <<endl; 
        std::size_t space2 = str3.find(" ");
        if (space2!=std::string::npos)
        str3=str3.substr(space2+1);
        //cout << str3 <<endl; 
	istringstream iss(str3);
	while ((iss)&&(!str.empty()))
     {
        string subs;
        iss >> subs;
	if (subs == "mov") {
       //  std::cout << "found!" << '\n';
         mov = str.find("mov");
         instrument = instrument+"movl ";
	}
	if(((subs.find("ip")!=std::string::npos) || (subs.find("sp")!=std::string::npos) || (subs.find("ax")!=std::string::npos) || (subs.find("bx")!=std::string::npos) || (subs.find("cx")!=std::string::npos) || (subs.find("dx")!=std::string::npos) || (subs.find("al")!=std::string::npos)||(subs.find("bl")!=std::string::npos)||  (subs.find("cl")!=std::string::npos) || (subs.find("dl")!=std::string::npos)) && (subs.find("[")==std::string::npos))
	{
	 instrument = instrument+"%"+subs;
	     if (subs.find(",")!=std::string::npos)
		instrument = instrument+" ";
	}
	if(subs.find("[")!=std::string::npos)
	{    std::size_t end=subs.find("]");
             if(subs.find("+")!=std::string::npos)
	      { plus=subs.find("+");
	        ref_plus=true;}
             if(subs.find("-")!=std::string::npos)
	      { minus=subs.find("-");
	        ref_minus=true;}
	     if((!ref_plus)&&(!ref_minus))
	       {
		instrument = instrument+"%("+subs.substr(1,end-1)+")";
		}
	     if((ref_plus))
	       {
		instrument = instrument+subs.substr(plus+1,end-1-plus)+"(%";
		instrument = instrument+subs.substr(1,plus-1)+")";
		}
	     if((ref_minus))
	       {
		instrument = instrument+subs.substr(minus,end-1-minus+1)+"(%";
		instrument = instrument+subs.substr(1,minus-1)+")";
		}	
	     if(subs.find(",")!=std::string::npos)
	      {
		instrument = instrument+", ";
		}
             ref_plus=false;
             ref_minus=false;
	}
	 else if(subs.find("x")!=std::string::npos)
                instrument=instrument+"$"+subs;  
       // cout << "Substring: " << subs << endl;
    } 
	
	std::size_t comma = instrument.find(",");
        if (comma!=std::string::npos)
        {
	string word1=instrument.substr(comma+2);
	std::size_t sp1 = instrument.find(" ");
        if (sp1!=std::string::npos)
	{
	string word2=instrument.substr(sp1+1,comma-sp1-1);
	string initial=instrument.substr(0,sp1+1);
	instrument=initial+word1+", "+word2;	
	}        
}

	//cout << str3 <<endl;
        //cout << "Enter contents to store in file (Enter # at end):\n";
        //  while ((c = getchar()) != '#') {
        out << "#include \"Dyn.h\" \n";
        out << "\n";
        out << "void Dyn::interleave(){\n";
        out << "asm(\"";
        out << instrument;
        out << "\"); \n";
	out << "} \n";
    //}
    out.close();
}
