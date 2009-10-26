#!C:\Progra~1\perl\bin\perl -w
##!/usr/local/bin/perl -w
#��������� ��������� ������ ���������� ������ ������� 3proxy
#����� � ���������� ������, ������� �����x � ��������� ��������������

use CGI;
use CGI::Carp(fatalsToBrowser);
use Net::SMTP;
use DateTime;
$query=new CGI;

#define constants
$cfgfile='config.cfg';
$ver='1.10.2';
#$path='/usr/local/apache/cgi-bin/proxy/';
$path='E:\local\cgi-bin\proxy';
open (CONFIG,"< $path\\$cfgfile") || die &error;
while(<CONFIG>){chomp;($key,$value)=split(/=/,$_);$const{$key}=$value;};
close CONFIG;

$month=$query->param('month');
$year=$query->param('year');
$filteroff=$query->param('filteroff');
$fname=$query->param('fname');
$action=$query->param('action');
$config=$query->param('config');
$var=$query->param('var');

&header;
if($action==0){&journal;}
elsif($action==1){&read;}
elsif($action==2){&report;}
elsif($action==3){&export_csv;}
elsif($action==4){&openfile;}
elsif($action==5){&config;}
elsif($action==6){&smtp;}
elsif($action==7){&read;}
elsif($action==9){&initiation;}
else{&error;}
&foot;

sub report()
{
print "<h3>����� � ��������� �������</h3>";
$total_bytes=0;
$total_files=0;
@files=sort {$a cmp $b} <$const{logdir}*.*>;
open (EXPORT,"> $path/$const{tempfile}") || die &error;
print EXPORT "Date;Login (IP);Bytes;\n";
$total_files=0;
foreach $file(@files)
{
($x,$fyear,$fmonth,$fday)=split('\.',$file);
	if($filteroff==0)
	{
		if($month==0)
		{
			if($fyear==$year)
			{$stat_date=$fday."/".$fmonth."/".$fyear;&export_conver;}
		}
		else
		{
			if($fmonth==$month && $fyear==$year)
			{$stat_date=$fday."/".$fmonth."/".$fyear;&export_conver;}
		}
	}
	else
	{$stat_date=$fday."/".$fmonth."/".$fyear;&export_conver;}
}
close EXPORT;
$rpt_total_bytes=$total_bytes/1000000;
$avg_traffic=0;if($total_files>0){$avg_traffic=$rpt_total_bytes/$total_files;}
print <<REPORT;
<P>��������� ������ ���������.<br>
���������� ������: $total_files<br>
REPORT
if($avg_traffic>0){print "������� ������ �������: $avg_traffic ��<br>"}
if($const{limit}>0 && $avg_traffic>0 && $const{deviation}>0)
{
	$rpt_limit=$const{limit}/1000000;
	$deviation=($const{deviation}*$avg_traffic)/100;
	print "������� �����: $rpt_limit Mb<br>";
	$from_deviation=$avg_traffic-$deviation;
	$till_deviation=$avg_traffic+$deviation;
	if($rpt_limit<($from_deviation) || $rpt_limit>($till_deviation))
	{print "������������� <a href=\"?action=9\" title='������� � ����� ���������'>������������� ������</a>: ";
	print "[$from_deviation - $till_deviation] ��<br>"}
}
print <<REPORT;
����� ����� �������: $rpt_total_bytes ��<br>
<a href="?action=4&var=1" style="color:#0066CC">��������� ����</a> |
<a href=\"javascript:window.close()" style="color:#0066CC\">�������</a></P>
REPORT
}

sub export_conver()
{
print "��������� �����: $file...";
open (FILE,"< $path/$file") || die "Can't open file: $file";
@data=<FILE>;
close (FILE);
%users=();
$tb_local=0; #local total bytes for file traffic count
foreach $data(@data)
{
($date,$time,$xlogin,$address,$rip,$lip,$bytes)=split(/\t/,$data);
#������ ������ �� IP address
$xlogin=$lip;
$users{$xlogin}=$users{$xlogin}+$bytes;
}
foreach $key (keys %users)
{
	if($key ne '0.0.0.0')
	{
		print EXPORT "$stat_date\;\"$key\";$users{$key}\;\n";
		$tb_local=$tb_local+$users{$key};
	}
}
	$total_bytes=$total_bytes+$tb_local;
	print "���������. ������: <a href=\"?action=1&fname=$file\" target=read>" . $tb_local/1000000 . "</a> ��. ";
	if ($const{limit}>0)
	{
		print '�����: <a ';
		$local_limit=$tb_local*100/$const{limit};
		if ($local_limit<=50){print '>';}
		elsif ($local_limit>50 && $local_limit<=100){print 'style="color:#0066CC">';}
		else {print 'style="color:#CC0000">';}
		print $local_limit . "%</a>";
	}
print '<br>';
$total_files++;
}

sub read()
{
if(!$fname)
{
	&get_fname();
}
print $fname;
open (FILE,"< $path/$fname") || die &error;
@data=<FILE>;
close (FILE);

if($action!=7)
{
	print "<h3>�������� �����: $fname</h3>";
	print "<form>����� �� ������������: <input type=text size=15 name=var value=$var> "; 
	print '<input type=hidden name=action value=1>';
	print "<input type=hidden name=fname value=$fname>";
	print '<input type=submit value=���������>';
	print "<P><a href=\"?fname=$fname&action=3&var=$var\" title=\"������� ������\">������� ������ � ������ CSV</a> | ";
	print"<a href=\"?fname=$fname&action=1\" title=\"�������� ���������� �� ���� �������������\">��� ������������</a>  | "; 
	print "<a href=\"javascript:window.close()\" style=\"color:#0066CC\">�������</a></P>";
	print '<P>';
}
%users=();
foreach $data(@data)
{
	($date,$time,$xlogin,$address,$rip,$lip,$bytes)=split(/\t/,$data);

	#���� ������ ����� �� ������������, �� ��������� ������
	if (length($var)!=0 && $action !=7)
	{
		#������ ������ �� IP �����
		$xlogin=$lip;		
		if ($var  eq $xlogin)
		{
			print '<PRE>';
			print "$date\t$time\t";
			($method,$url,$http)=split(/ /,$address);
			$method=undef;
			$http=undef;
			$url=undef;			
			#print "<a href=\"$url\" target=_blank>$address</a>";
			print "$rip\t$lip\t\t$bytes";
			$bt=$bt+$bytes;
			print '</PRE>';
		}
	}	

	#����� ���� �������� � �������������
	else
	{
		#������ ������ �� IP �����
		$xlogin=$lip;
		$users{$xlogin}=$users{$xlogin}+$bytes;		
	}
}

if (length($var)==0)
{
	my @keys = sort {$a cmp  $b} keys %users;
	print '<table border=0><tr><td><b>IP �����</b></td><td><b>�����</b></td></tr>';
	foreach $key (@keys)
	{
		if($key ne '0.0.0.0')
		{
			print "<tr><td><i><a href=\"?action=1&var=$key&fname=$fname\">$key</i></td><td>". $users{$key}/1000000 	."</td></tr>\n";
			$bt=$bt+$users{$key};	
		}	
	}
	$bt=$bt/1000000;
	print "<tr><td><b>�����:</b></td><td>$bt</td></tr>";
	$cost=$bt*$const{'cost'};
	print "<tr><td><b>�����:</b></td><td>$cost</td></tr></table>";
}
else
{
	if($action!=7)
	{
		print '<hr width=100%>';
		$bt=$bt/1000000;
		print "<b>�����:</b> <i>$bt ��</i>";
	}
	else
	{
		$trafstat=$users{$var}/1000000;
		print '<TR><TD><IMG SRC="/img/ism/traf.gif"></TD><TD STYLE="color:#000000" TITLE="������������ ������">'.$trafstat.' Mb</TD></TR>';
		$cost=$trafstat*$const{'cost'};
		print '<TR><TD><IMG SRC="/img/ism/cash.gif"></TD><TD TITLE="��������� ��������� �������">'.$cost.' �.</TD></TR>';
		print '<TR ALIGN=CENTER><TD COLSPAN=2><A HREF="?action=7">��������</A></TD></TR></TABLE>';
	}
}
if($action!=7)
{
	print"<P><a href=\"?fname=$fname&action=6&var=$bt\" title=\"����� �� ����������� �����\">��������� �����</a></P>";
}
if($send)
{
	print "\n\nStarting to send traffic data...";
	$var=$bt;
	&smtp();
	$send=undef;
	print 'complete';
}
}

sub journal()
{
&set_period;
print <<MENU;
<P>����: <a href="?action=2&month=$month&year=$year&filteroff=$filteroff" style="color:#0066CC" target=export title="��������� ������">����� � ��������� �������</a> | <a href="?action=5&var=2" style="color:#0066CC" title="������������� ������������ ������">������������ ������</a> | <a href="?action=9" style="color:#0066CC" title="������������� ���������">���������</a> | <a href="#" OnClick="javascript:window.open('?action=7','traf','width=150, height=120, left=600, top=400,toolbar=0, location=0, directories=0, menubar=0, scrollbars=0, resizable=1, status=0, fullscreen=0')" style="color:#087700" title="���������� ��������� �������">��������� �������</a> | <a href="?action=4" style="color:#0066CC" title="���������� ����������" target=_help>������</a></P>
MENU
print '<h3>������ ������ ����������</h3>';
@files=sort {$a cmp $b} <$const{logdir}log.*>;
print '<table border=0 bgcolor=#EEEEEE cellpadding=5 cellspacing=1><tr><td bgcolor=#EEEEFF colspan=2>';
print '������ ������������ �������</td></tr><tr bgcolor=#FFFFFF><td>';
print '<form method=post>';
print '����� �� ������: <select name=month ';
if($filteroff==1){print 'disabled';}
print '>';
for ($n=0;$n<=12;$n++){print '<option '; if($month==$n && $filteroff==0){print 'selected';};print ">$n"}
print '</select> ���: <select name=year ';
if($filteroff==1){print 'disabled';}
print '>';
for ($n=2007;$n<=2009;$n++){print '<option ';if($year==$n && $filteroff==0){print 'selected'};print ">$n"}
print '</select><br><a href="?" style="color:#0066CC" title="����� ������ �������� ������">������� �����</a></td><td>'. localtime() .'</td></tr>';
print '<tr bgcolor=#FFFFFF><td>��������� ����� <input type=checkbox name=filteroff value=1 ';
if($filteroff==1){print 'checked';}
print '></td><td><input type=submit value=���������></form></td></tr></table><OL>';
foreach $file(@files)
{
	($x,$fyear,$fmonth,$fday)=split('\.',$file);
	if($filteroff==0)
	{
		if($month==0)
		{	
			if($fyear==$year) 
			{
				print "<LI><a href=\"?action=1&fname=$file\" target=read>���� ���������� ";
				print $fyear .".". $fmonth .".". $fday ."</a>";
			}
		}
		else
		{	
			if($fmonth==$month && $fyear==$year) 
			{
				print "<LI><a href=\"?action=1&fname=$file\" target=read>���� ���������� ";
				print $fyear .".". $fmonth .".". $fday ."</a>";
			}
		}
	}
	else
	{print "<LI><a href=\"?action=1&fname=$file\" target=read>���� ���������� ". $fyear .".". $fmonth .".". $fday ."</a>";}
}
print '</OL>';
}

#��������� ��������� ������� ������� �� ������ �������� ������
sub set_period()
{
	if ($month ==0 && $year==0)
	{
		($x,$x,$x,$day,$month,$year)=localtime(time);
		$month=$month+1;$year=$year+1900;
		$day=undef;
	}
}

sub header()
{
if ($action==4 && $var==1)
{
	print "Content-type: text/csv\n\n";
}
else{
	if($action==7)
	{
		print $query->header(-charset=>'windows-1251',-refresh=>$const{'refresh'},-Cache_control=>"no-cache");
	}
	else
	{
		print "Content-type: text/html\n\n";
		print '<html><meta http-equiv="Content-type" content="text/html; charset=windows-1251">';
	}
print "<head><title>ISM $ver</title>";
print '<style type="text/css">';
print 'body {font-family:Verdana;font-size:12px}'; 
print 'form {font-family:Verdana;font-size:12px}';
print 'table {font-family:Verdana;font-size:12px}';
print '</style></head>';
print "<body link=#0066CC vlink=#0066CC text=#5A5A5A>\n";
}
}

sub foot()
{
if ($action==4 && $var==1){}
elsif($action==7){print '</body></html>'}
else{
print <<SUBSCRIBE;
<P align=right>ISM - internet statistic monitor�<br>
<a href="http://msvirid.kras.ru/opensource/">http://msvirid.kras.ru/opensource/</a><br>
Contacts: <a href="mailto:msvirid\@kras.ru">msvirid\@kras.ru</a></P></body></html>
SUBSCRIBE
}
}

#��������� ���������� ����� � ������ CSV
sub export_csv()
{
print '<h3>������� ������ � ������ CSV</h3>';
print "������� ������ �� �����: $fname � ������ CSV ";
open (FILE,"< $path/$fname") || die &error;
@data=<FILE>;
close (FILE);
open (EXPORT,"> $path/$const{tempfile}") || die &error;
print EXPORT "Date;Time;Login;URL;RIP;LIP;Bytes\n";
foreach $data(@data)
{
	($date,$time,$xlogin,$address,$rip,$lip,$bytes)=split(/\t/,$data);
	#������ ������ �� IP
	$xlogin=$lip;
	if (length($var)==0){print EXPORT "$date;$time;\"$xlogin\";\"$address\";\"$rip\";\"$lip\";$bytes";}
	else{if ($var eq $xlogin){print EXPORT "$date;$time;\"$xlogin\";\"$address\";\"$rip\";\"$lip\";$bytes";}}
}
close(EXPORT);
print '��������.';
print "<P><a href=\"?action=4&var=1\" style=\"color:#0066CC\">��������� ����</a> | <a href=\"javascript:window.close()\" style=\"color:#0066CC\">�������</a></P>";
}

sub initiation()
{
print '<h3>�������������� ��������:</h3><table>';
if ($var ne '' && $config ne '')
{
	open (CONFIG, "> $path/$cfgfile") || die &error;
	foreach $key(keys %const)
	{
		if($var eq $key)
		{
			print CONFIG "$key=$config\n"
		}
		else
		{
			print CONFIG "$key=$const{$key}\n"
		}
	}
	close CONFIG;
	print "<P>��������� ������� ���������.</P>";
}
else
{
	@keys=sort {$a cmp $b} keys %const;
	foreach $key(@keys)
		{
		print "<tr><td bgcolor=#F0F0F0>$key:</td><td><form action=\"?\" method=post></td><td>";
		print "<input type=text name=config size=50 value=$const{$key}></td><td>";
		print "<input type=hidden name=action value=9><input type=hidden name=var value=$key>";
		print "<input type=submit value=���������></td><td></form></td></tr>\n"
		}
}
print '</table><P><a href="?action=9">��������</a> | <a href="?action=4&var=5" target=blank>��������� � ����</a> | <a href="?">�������</a></P>';
}

#Error message
sub error()
{
print '<h3>������, ��������� �������� �����������.</h3>';
print "��� ������:  $ENV{QUERY_STRING}\#$ver";
print '<P>���������� ��������:<OL><LI>������� ������ ������� <LI>��������� ��������� ��������';
print '<LI>��� ��������� ������������� ������ <a href="?action=9">��������� ���������</a>';
print '<LI>���� ������ �� �������, �������� ';
print "<a href=\"mailto:$const{admin}?subject=Bug_report-ISM-$ver\">��������������</a> ��� ������ � ������� �������� ��� ������� ��������� ������</OL></P>";
print '<a href="?">�������</a>';
}

#Open file module
sub openfile()
{
$file=$const{helpfile};
if($var==1){$file=$const{tempfile};}
elsif($var==2){$file=$const{proxy};}
elsif($var==3){$file=$const{cnfarc};}
elsif($var==4){$file=$const{chglog};}
elsif($var==5){$file=$cfgfile;}
open (RFILE,"< $path/$file") || die &error;while (<RFILE>){print $_}close RFILE;
}

#Configuration editor
sub config()
{
print '<h3>�������� ������������ ������ �������</h3>';
if($config ne '')
{
	if($var==1){$text='��������';$file=$const{proxy}}
	elsif($var==2){$text='�������� � �����';$file=$const{cnfarc}}
	elsif($var==3){$text='������������ �� ������';$file=$const{proxy}}
	open (WFILE,"> $path/$file") || die &error;
	if($var==1){print WFILE $config}
	elsif($var==2){print WFILE '#---Saved configuration at '. localtime()."---\n".$config."\n#---EOF---\n";}
	elsif($var==3)
	{
	open(RFILE,"< $path/$const{cnfarc}") || die &error;
	@config=<RFILE>;
	close RFILE;
	print WFILE @config;
	}
	close WFILE;
	print '<P>���� ������������ ������� '.$text.': '.localtime().'</P>';
}
print '<form action="?" method=post><input type=hidden name=action value=5><textarea cols=80 rows=16 name=config>';
$var=2; &openfile;
print '</textarea><P>'; 
print '<select name=var><option value=1>���������<option value=2>������������<option value=3>������������</select>';
print ' <input type=submit value=��> <input type=reset value=��������></P></form>';
print '<a href="?action=4&var=3" target=config title=\'������� �������� ������������\'>�������� ������������</a> | <a href="?">�������</a>';
}

sub smtp()
{
print '<h3>�������� ������ �� ����������� �����</h3>';
my @rcpt=split(',',$const{'recipient'});
my $smtp=Net::SMTP->new(Host => $const{'smtp'},
			Hello => $const{'smtp'},
			Port=> $const{'port'},
			Debug => 0,
			);
print '���� ����������: '. $fname .'<br>';
print '����� SMTP: '. $smtp->domain() .'<br>';
print '�������������: '. $smtp->banner() .'<br>';
foreach my $rcpt (@rcpt)
{
print "����������: $rcpt<br>";
$smtp->mail($const{'admin'});
$smtp->recipient($rcpt,{SkipBad => 1});
$smtp->data();
$smtp->datasend("To: $rcpt\n");
$smtp->datasend("Subject: Internet statistic report\n");
$smtp->datasend("\n");
$smtp->datasend("���������� �������� ������� �� $fname\n\n");
$smtp->datasend("����� ������: $var Mb\n\n");
$smtp->datasend("����������� �����������: http://192.168.0.11/cgi-bin/proxy/istat.pl?action=1&fname=$fname\n");
$smtp->datasend("����������� � ������� CSV: http://192.168.0.11/cgi-bin/proxy/istat.pl?fname=$fname&action=3\n");
$smtp->datasend("����� ������: " . localtime());
$smtp->datasend("\n----\n������������ �������� ISM $ver\nhttp://www.msvirid.kras.ru/opensource/ism/");
$smtp->datasend("\n-----------------------------------------------------------------------\n");
$smtp->datasend("Internet statistic report at $fname\n\n");
$smtp->datasend("Total traffic: $var Mb\n\n");
$smtp->datasend("See logfile: http://192.168.0.11/cgi-bin/proxy/istat.pl?action=1&fname=$fname\n");
$smtp->datasend("Get CSV file: http://192.168.0.11/cgi-bin/proxy/istat.pl?fname=$fname&action=3\n");
$smtp->datasend("Message created: " . localtime());
$smtp->datasend("\n----\nGenerated by ISM $ver\nhttp://www.msvirid.kras.ru/opensource/ism/");
$smtp->dataend();
$smtp->verify($rcpt);
}
$smtp->quit;
print '���������� ���������<P><a href="javascript:window.close()" style="color:#0066CC">�������</a></P>';
}

sub get_fname()
{
	my $setFname=DateTime->now();#time_zone=>'Europe/Moscow')->add(hours=>4);
	#print "\n\n\n\n$setFname\n\n\n\n";
	if($action==7)
	{
		$var=$ENV{'REMOTE_ADDR'};
		print '<TABLE BORDER=0><TR><TD><IMG SRC="/img/ism/clock.gif"></TD><TD style="color:#087700" TITLE="����� ���������� ���������� ������">'.$setFname->time.'</TD></TR>';
		print '<TR><TD><IMG SRC="/img/ism/comp.gif"></TD><TD style="color:#176fc1" TITLE="IP ����� �������">'.$var.'</TD></TR>';		
	}
	else
	{
		$setFname->subtract(days=>1);
		$send=1;
	}
	$fname=$const{'logdir'}.'log.'.$setFname->ymd('.');
	#print "\n\n\n\n$fname\n\n\n\n";	
}