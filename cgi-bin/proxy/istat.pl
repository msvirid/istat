#!C:\Progra~1\perl\bin\perl -w
##!/usr/local/bin/perl -w
#Программа просмотра файлов статистики прокси сервера 3proxy
#Отбор и сортировка данных, экспорт данныx о суммарной потребляемости

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
print "<h3>Отчет о суммарном трафике</h3>";
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
<P>Обработка данных завершена.<br>
Обработано файлов: $total_files<br>
REPORT
if($avg_traffic>0){print "Средний расход трафика: $avg_traffic Мб<br>"}
if($const{limit}>0 && $avg_traffic>0 && $const{deviation}>0)
{
	$rpt_limit=$const{limit}/1000000;
	$deviation=($const{deviation}*$avg_traffic)/100;
	print "Текущий лимит: $rpt_limit Mb<br>";
	$from_deviation=$avg_traffic-$deviation;
	$till_deviation=$avg_traffic+$deviation;
	if($rpt_limit<($from_deviation) || $rpt_limit>($till_deviation))
	{print "Рекомендуется <a href=\"?action=9\" title='Переход в режим настройки'>корректировка лимита</a>: ";
	print "[$from_deviation - $till_deviation] Мб<br>"}
}
print <<REPORT;
Общий объем трафика: $rpt_total_bytes Мб<br>
<a href="?action=4&var=1" style="color:#0066CC">Сохранить файл</a> |
<a href=\"javascript:window.close()" style="color:#0066CC\">Закрыть</a></P>
REPORT
}

sub export_conver()
{
print "Обработка файла: $file...";
open (FILE,"< $path/$file") || die "Can't open file: $file";
@data=<FILE>;
close (FILE);
%users=();
$tb_local=0; #local total bytes for file traffic count
foreach $data(@data)
{
($date,$time,$xlogin,$address,$rip,$lip,$bytes)=split(/\t/,$data);
#замена логина на IP address
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
	print "завершена. Трафик: <a href=\"?action=1&fname=$file\" target=read>" . $tb_local/1000000 . "</a> Мб. ";
	if ($const{limit}>0)
	{
		print 'Лимит: <a ';
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
	print "<h3>Просмотр файла: $fname</h3>";
	print "<form>Отбор по пользователю: <input type=text size=15 name=var value=$var> "; 
	print '<input type=hidden name=action value=1>';
	print "<input type=hidden name=fname value=$fname>";
	print '<input type=submit value=Применить>';
	print "<P><a href=\"?fname=$fname&action=3&var=$var\" title=\"Экспорт данных\">Экспорт данных в формат CSV</a> | ";
	print"<a href=\"?fname=$fname&action=1\" title=\"Показать статистику по всем пользователям\">Все пользователи</a>  | "; 
	print "<a href=\"javascript:window.close()\" style=\"color:#0066CC\">Закрыть</a></P>";
	print '<P>';
}
%users=();
foreach $data(@data)
{
	($date,$time,$xlogin,$address,$rip,$lip,$bytes)=split(/\t/,$data);

	#Если выбран отбор по пользователю, то суммируем трафик
	if (length($var)!=0 && $action !=7)
	{
		#замена логина на IP адрес
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

	#Иначе сбор сведений о пользователях
	else
	{
		#замена логина на IP адрес
		$xlogin=$lip;
		$users{$xlogin}=$users{$xlogin}+$bytes;		
	}
}

if (length($var)==0)
{
	my @keys = sort {$a cmp  $b} keys %users;
	print '<table border=0><tr><td><b>IP адрес</b></td><td><b>МБайт</b></td></tr>';
	foreach $key (@keys)
	{
		if($key ne '0.0.0.0')
		{
			print "<tr><td><i><a href=\"?action=1&var=$key&fname=$fname\">$key</i></td><td>". $users{$key}/1000000 	."</td></tr>\n";
			$bt=$bt+$users{$key};	
		}	
	}
	$bt=$bt/1000000;
	print "<tr><td><b>Итого:</b></td><td>$bt</td></tr>";
	$cost=$bt*$const{'cost'};
	print "<tr><td><b>Сумма:</b></td><td>$cost</td></tr></table>";
}
else
{
	if($action!=7)
	{
		print '<hr width=100%>';
		$bt=$bt/1000000;
		print "<b>Итого:</b> <i>$bt Мб</i>";
	}
	else
	{
		$trafstat=$users{$var}/1000000;
		print '<TR><TD><IMG SRC="/img/ism/traf.gif"></TD><TD STYLE="color:#000000" TITLE="Потребленный трафик">'.$trafstat.' Mb</TD></TR>';
		$cost=$trafstat*$const{'cost'};
		print '<TR><TD><IMG SRC="/img/ism/cash.gif"></TD><TD TITLE="Расчетная стоимость трафика">'.$cost.' р.</TD></TR>';
		print '<TR ALIGN=CENTER><TD COLSPAN=2><A HREF="?action=7">Обновить</A></TD></TR></TABLE>';
	}
}
if($action!=7)
{
	print"<P><a href=\"?fname=$fname&action=6&var=$bt\" title=\"Отчет по электронной почте\">Отправить отчет</a></P>";
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
<P>Меню: <a href="?action=2&month=$month&year=$year&filteroff=$filteroff" style="color:#0066CC" target=export title="Суммарный трафик">Отчет о суммарном трафике</a> | <a href="?action=5&var=2" style="color:#0066CC" title="Редактировать конфигурацию прокси">Конфигурация прокси</a> | <a href="?action=9" style="color:#0066CC" title="Редактировать настройки">Настройки</a> | <a href="#" OnClick="javascript:window.open('?action=7','traf','width=150, height=120, left=600, top=400,toolbar=0, location=0, directories=0, menubar=0, scrollbars=0, resizable=1, status=0, fullscreen=0')" style="color:#087700" title="Отобразить индикатор трафика">Индикатор трафика</a> | <a href="?action=4" style="color:#0066CC" title="Справочная информация" target=_help>Помощь</a></P>
MENU
print '<h3>Журнал файлов статистики</h3>';
@files=sort {$a cmp $b} <$const{logdir}log.*>;
print '<table border=0 bgcolor=#EEEEEE cellpadding=5 cellspacing=1><tr><td bgcolor=#EEEEFF colspan=2>';
print 'Период формирования журнала</td></tr><tr bgcolor=#FFFFFF><td>';
print '<form method=post>';
print 'Отбор по месяцу: <select name=month ';
if($filteroff==1){print 'disabled';}
print '>';
for ($n=0;$n<=12;$n++){print '<option '; if($month==$n && $filteroff==0){print 'selected';};print ">$n"}
print '</select> год: <select name=year ';
if($filteroff==1){print 'disabled';}
print '>';
for ($n=2007;$n<=2009;$n++){print '<option ';if($year==$n && $filteroff==0){print 'selected'};print ">$n"}
print '</select><br><a href="?" style="color:#0066CC" title="Отбор файлов текущего месяца">Текущий месяц</a></td><td>'. localtime() .'</td></tr>';
print '<tr bgcolor=#FFFFFF><td>отключить отбор <input type=checkbox name=filteroff value=1 ';
if($filteroff==1){print 'checked';}
print '></td><td><input type=submit value=Применить></form></td></tr></table><OL>';
foreach $file(@files)
{
	($x,$fyear,$fmonth,$fday)=split('\.',$file);
	if($filteroff==0)
	{
		if($month==0)
		{	
			if($fyear==$year) 
			{
				print "<LI><a href=\"?action=1&fname=$file\" target=read>Файл статистики ";
				print $fyear .".". $fmonth .".". $fday ."</a>";
			}
		}
		else
		{	
			if($fmonth==$month && $fyear==$year) 
			{
				print "<LI><a href=\"?action=1&fname=$file\" target=read>Файл статистики ";
				print $fyear .".". $fmonth .".". $fday ."</a>";
			}
		}
	}
	else
	{print "<LI><a href=\"?action=1&fname=$file\" target=read>Файл статистики ". $fyear .".". $fmonth .".". $fday ."</a>";}
}
print '</OL>';
}

#Процедура установки периода журнала на начало текущего месяца
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
<P align=right>ISM - internet statistic monitor©<br>
<a href="http://msvirid.kras.ru/opensource/">http://msvirid.kras.ru/opensource/</a><br>
Contacts: <a href="mailto:msvirid\@kras.ru">msvirid\@kras.ru</a></P></body></html>
SUBSCRIBE
}
}

#Процедура сохранения файла в формат CSV
sub export_csv()
{
print '<h3>Экспорт данных в формат CSV</h3>';
print "Экспорт данных из файла: $fname в формат CSV ";
open (FILE,"< $path/$fname") || die &error;
@data=<FILE>;
close (FILE);
open (EXPORT,"> $path/$const{tempfile}") || die &error;
print EXPORT "Date;Time;Login;URL;RIP;LIP;Bytes\n";
foreach $data(@data)
{
	($date,$time,$xlogin,$address,$rip,$lip,$bytes)=split(/\t/,$data);
	#замена логина на IP
	$xlogin=$lip;
	if (length($var)==0){print EXPORT "$date;$time;\"$xlogin\";\"$address\";\"$rip\";\"$lip\";$bytes";}
	else{if ($var eq $xlogin){print EXPORT "$date;$time;\"$xlogin\";\"$address\";\"$rip\";\"$lip\";$bytes";}}
}
close(EXPORT);
print 'завершен.';
print "<P><a href=\"?action=4&var=1\" style=\"color:#0066CC\">Сохранить файл</a> | <a href=\"javascript:window.close()\" style=\"color:#0066CC\">Закрыть</a></P>";
}

sub initiation()
{
print '<h3>Редактирование настроек:</h3><table>';
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
	print "<P>Настройки успешно сохранены.</P>";
}
else
{
	@keys=sort {$a cmp $b} keys %const;
	foreach $key(@keys)
		{
		print "<tr><td bgcolor=#F0F0F0>$key:</td><td><form action=\"?\" method=post></td><td>";
		print "<input type=text name=config size=50 value=$const{$key}></td><td>";
		print "<input type=hidden name=action value=9><input type=hidden name=var value=$key>";
		print "<input type=submit value=Сохранить></td><td></form></td></tr>\n"
		}
}
print '</table><P><a href="?action=9">Обновить</a> | <a href="?action=4&var=5" target=blank>Сохранить в файл</a> | <a href="?">Закрыть</a></P>';
}

#Error message
sub error()
{
print '<h3>Ошибка, вызванное действие недопустимо.</h3>';
print "Код ошибки:  $ENV{QUERY_STRING}\#$ver";
print '<P>Дальнейшие действия:<OL><LI>нажмите кнопку Закрыть <LI>Повторите выбранное действие';
print '<LI>При повторном возникновении ошибки <a href="?action=9">проверьте настройки</a>';
print '<LI>Если ничего не помогло, сообщите ';
print "<a href=\"mailto:$const{admin}?subject=Bug_report-ISM-$ver\">администратору</a> код ошибки и опишите действия при которых возникает ошибка</OL></P>";
print '<a href="?">Закрыть</a>';
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
print '<h3>Редактор конфигурации прокси сервера</h3>';
if($config ne '')
{
	if($var==1){$text='сохранен';$file=$const{proxy}}
	elsif($var==2){$text='добавлен в архив';$file=$const{cnfarc}}
	elsif($var==3){$text='восстановлен из архива';$file=$const{proxy}}
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
	print '<P>Файл конфигурации успешно '.$text.': '.localtime().'</P>';
}
print '<form action="?" method=post><input type=hidden name=action value=5><textarea cols=80 rows=16 name=config>';
$var=2; &openfile;
print '</textarea><P>'; 
print '<select name=var><option value=1>Сохранить<option value=2>Архивировать<option value=3>Восстановить</select>';
print ' <input type=submit value=Ок> <input type=reset value=Отменить></P></form>';
print '<a href="?action=4&var=3" target=config title=\'Открыть архивную конфигурацию\'>Архивная конфигурация</a> | <a href="?">Закрыть</a>';
}

sub smtp()
{
print '<h3>Отправка отчета по электронной почте</h3>';
my @rcpt=split(',',$const{'recipient'});
my $smtp=Net::SMTP->new(Host => $const{'smtp'},
			Hello => $const{'smtp'},
			Port=> $const{'port'},
			Debug => 0,
			);
print 'Файл статистики: '. $fname .'<br>';
print 'Домен SMTP: '. $smtp->domain() .'<br>';
print 'Инициализация: '. $smtp->banner() .'<br>';
foreach my $rcpt (@rcpt)
{
print "Получатель: $rcpt<br>";
$smtp->mail($const{'admin'});
$smtp->recipient($rcpt,{SkipBad => 1});
$smtp->data();
$smtp->datasend("To: $rcpt\n");
$smtp->datasend("Subject: Internet statistic report\n");
$smtp->datasend("\n");
$smtp->datasend("Статистика интернет трафика за $fname\n\n");
$smtp->datasend("Общий трафик: $var Mb\n\n");
$smtp->datasend("Просмотреть детализацию: http://192.168.0.11/cgi-bin/proxy/istat.pl?action=1&fname=$fname\n");
$smtp->datasend("Детализация в формате CSV: http://192.168.0.11/cgi-bin/proxy/istat.pl?fname=$fname&action=3\n");
$smtp->datasend("Отчет создан: " . localtime());
$smtp->datasend("\n----\nСформировано системой ISM $ver\nhttp://www.msvirid.kras.ru/opensource/ism/");
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
print 'Соединение завершено<P><a href="javascript:window.close()" style="color:#0066CC">Закрыть</a></P>';
}

sub get_fname()
{
	my $setFname=DateTime->now();#time_zone=>'Europe/Moscow')->add(hours=>4);
	#print "\n\n\n\n$setFname\n\n\n\n";
	if($action==7)
	{
		$var=$ENV{'REMOTE_ADDR'};
		print '<TABLE BORDER=0><TR><TD><IMG SRC="/img/ism/clock.gif"></TD><TD style="color:#087700" TITLE="Время последнего обновления данных">'.$setFname->time.'</TD></TR>';
		print '<TR><TD><IMG SRC="/img/ism/comp.gif"></TD><TD style="color:#176fc1" TITLE="IP адрес клиента">'.$var.'</TD></TR>';		
	}
	else
	{
		$setFname->subtract(days=>1);
		$send=1;
	}
	$fname=$const{'logdir'}.'log.'.$setFname->ymd('.');
	#print "\n\n\n\n$fname\n\n\n\n";	
}