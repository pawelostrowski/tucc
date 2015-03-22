#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Tunel Ucieszony Chat Client
# TUCC is sipmle tunel with Python for UCC
# Copyright (C) 2015 Paweł Ostrowski
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Tunel Ucieszony Chat Client (in the file LICENSE); if not,
# see <http://www.gnu.org/licenses/gpl-2.0.html>.

###############################################################################
# Ustawienia podstawowe:
#
# Uwaga!
# Nie jest sprawdzana poprawność danych konfiguracji (w sensie samego ich wprowadzenia),
# bo to tunel na serwerze i zwykły użytkownik nie ma na niego wpływu.
# Za poprawność wprowadzonych danych odpowiada osoba uruchamiająca tunel na serwerze.

# port, na którym pracuje tunel
tunel_port = 8888

# UCC wysyła tu zuoUsername, tunel dla odróżnienia wyśle informację specjalną
tunel_name = "Tunel Ucieszony Chat Client"

# User-Agent udawanej przeglądarki internetowej
browser_ver = "36.0"
browser_ua = "Mozilla/5.0 (X11; Linux x86_64; rv:%s) Gecko/20100101 Firefox/%s" % (browser_ver, browser_ver)

# wersja apletu, którą udaje tunel
applet_ver = "1.1(20140526-0005 - R)"

# próbuj wykonać całą autoryzację przez SSL, a nie tylko samo hasło, w razie problemów można zmienić na 'True' na 'False'
all_auth_https = True
###############################################################################


# ta wersja skryptu dopasowana jest do trzeciej wersji Pythona, z wersją drugą w obecnej formie skrypt nie działałby
import sys

if sys.version[0] != "3":
	print("Wykryto wersję Pythona nieobsługiwaną przez skrypt. Proszę użyć wersji 3.x")
	exit(1)

del sys


# celowo nie używam 'from', aby było widać, z czego pochodzą funkcje
import _thread as thread
import time
import socket
import signal
import select
import re


def get_date_time(con_id):
	date_time = time.strftime("[%a, %d %b %Y, %H:%M:%S] -!- ")
	date_time += "(%d) " % con_id
	return date_time


def signal_break(signal, frame):
	# przejście do nowego wiersza, aby ^C nie psuło wyglądu powiadomień
	sock_main.close()
	print("\nKończenie działania tunelu...")
	exit(0)


def thread_end(sock_client, con_id):
	sock_client.close()
	print("%sZakończono obsługę tego połączenia." % get_date_time(con_id))
	thread.exit_thread()


def send_client_info(sock_client, buf_str):
	# wyślij informację do klienta w RAW 666
	# jako parametr przyjmowany jest string w UTF-8 i wysyłane są dane w ISO-8859-2
	buf_str_raw = ":tucc 666 tucc :%s\r\n" % buf_str

	try:
		sock_client.send(buf_str_raw.encode('iso-8859-2'))

	except socket.error:
		thread_end(sock_client, con_id)


def send_onet_str(sock_client, sock_irc, buf_str):
	# wyślij string w UTF-8 jako dane w ISO-8859-2
	# dodaj "\r\n" na końcu, aby nie trzeba było go dopisywać w parametrach
	buf_str += "\r\n"

	try:
		sock_irc.send(buf_str.encode('iso-8859-2'))

	except socket.error:
		sock_irc.close()
		thread_end(sock_client, con_id)


def recv_onet_str(sock_client, sock_irc):
	# zwróć dane w ISO-8859-2 jako string w UTF-8 (to wynika z drugiej linii skryptu)
	try:
		return sock_irc.recv(1500).decode('iso-8859-2')

	except socket.error:
		sock_irc.close()
		thread_end(sock_client, con_id)


def http(sock_client, con_id, auth_step, method, host, port, stock, content, cookies):
	send_client_info(sock_client, auth_step + "...")

	# gniazdo HTTP(S): IPv4, TCP
	sock_http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# jeśli trzeba, połączenie nieszyfrowane zastąp połączeniem zaszyfrowanym
	if all_auth_https:
		port = 443

	# połącz z hostem
	try:
		sock_http.connect((host, port))

	except socket.error:
		sock_http.close()
		print("%s%s: Nie udało się połączyć z: %s" % (get_date_time(con_id), auth_step, host))
		send_client_info(sock_client, "\x02Nie udało się połączyć z: %s" % host)
		thread_end(sock_client, con_id)

	# utwórz zapytanie do hosta
	data_send = 		"%s %s HTTP/1.1\r\n" \
				"Host: %s\r\n" \
				"User-Agent: %s\r\n" \
				"Accept-Language: pl\r\n" \
				% (method, stock, host, browser_ua)

	if method == "POST":
		data_send +=	"Content-Type: application/x-www-form-urlencoded\r\n" \
				"Content-Length: %d\r\n" % len(content)

	if cookies != "":
		data_send +=	"Cookie:%s\r\n" % cookies

	data_send +=		"Connection: close\r\n\r\n"

	if content != "":
		data_send +=	content

	# połączenie nieszyfrowane
	if port != 443:
		# wyślij zapytanie do hosta
		try:
			sock_http.send(data_send.encode('iso-8859-2'))

		except socket.error:
			sock_http.close()
			print("%s%s: Nie udało się wysłać danych do: %s" % (get_date_time(con_id), auth_step, host))
			send_client_info(sock_client, "\x02Nie udało się wysłać danych do: %s" % host)
			thread_end(sock_client, con_id)

		# pobierz odpowiedź od hosta
		try:
			data_recv = sock_http.recv(1500)

		except socket.error:
			sock_http.close()
			print("%s%s: Nie udało się pobrać danych z: %s" % (get_date_time(con_id), auth_step, host))
			send_client_info(sock_client, "\x02Nie udało się pobrać danych z: %s" % host)
			thread_end(sock_client, con_id)

	# połączenie na porcie 443 będzie zaszyfrowane
	else:
		import ssl

		sock_ssl = ssl.wrap_socket(sock_http)

		# wyślij zapytanie do hosta (SSL)
		try:
			sock_ssl.write(data_send.encode('iso-8859-2'))

		except socket.error:
			del sock_ssl
			del ssl
			sock_http.close()
			print("%s%s: Nie udało się wysłać danych do: %s [SSL]" % (get_date_time(con_id), auth_step, host))
			send_client_info(sock_client, "\x02Nie udało się wysłać danych do: %s [SSL]" % host)
			thread_end(sock_client, con_id)

		# pobierz odpowiedź od hosta (SSL)
		try:
			data_recv = sock_ssl.read(1500)

		except socket.error:
			del sock_ssl
			del ssl
			sock_http.close()
			print("%s%s: Nie udało się pobrać danych z: %s [SSL]" % (get_date_time(con_id), auth_step, host))
			send_client_info(sock_client, "\x02Nie udało się pobrać danych z: %s [SSL]" % host)
			thread_end(sock_client, con_id)

		del sock_ssl
		del ssl

	sock_http.close()

	# zwróć jako string przekodowany z ISO-8859-2 na UTF-8 (to wynika z drugiej linii skryptu)
	return data_recv.decode('iso-8859-2')


def get_cookies(data_recv):
	cookies_tmp = re.findall("Set-Cookie:(.+?;)", data_recv)
	return "".join(cookies_tmp)


def auth_http(sock_client, con_id, nick, passwd):
	cookies = ""

	data_recv = http(sock_client, con_id, "authHttpInit", "GET", "kropka.onet.pl", 80, "/_s/kropka/5?DV=czat/applet/FULL", "", cookies)

	cookies = get_cookies(data_recv)

	data_recv = http(sock_client, con_id, "authHttpGetSk", "GET", "czat.onet.pl", 80, "/sk.gif", "", cookies)

	cookies += get_cookies(data_recv)

	data_recv = http(sock_client, con_id, "authHttpMLogin", "POST", "secure.onet.pl", 443, "/mlogin.html", \
		"r=&url=&login=%s&haslo=%s&app_id=20&ssl=1&ok=1" % (nick, passwd), cookies)

	cookies += get_cookies(data_recv)

	data_recv = http(sock_client, con_id, "authHttpGetUoKey", "POST", "czat.onet.pl", 80, "/include/ajaxapi.xml.php3", \
		"api_function=getUoKey&params=a:3:{s:4:\"nick\";s:%d:\"%s\";s:8:\"tempNick\";i:0;s:7:\"version\";s:%d:\"%s\";}" % \
		(len(nick), nick, len(applet_ver), applet_ver), cookies)

	uokey_start = data_recv.find("<uoKey>")
	uokey_end = data_recv.find("</uoKey>")

	zuousername_start = data_recv.find("<zuoUsername>")
	zuousername_end = data_recv.find("</zuoUsername>")

	if uokey_start != -1 and uokey_end != -1 and zuousername_start != -1 and zuousername_end != -1:
		return (data_recv[uokey_start + 7:uokey_end], data_recv[zuousername_start + 13:zuousername_end])

	else:
		# gdy nie znaleziono uoKey i/lub zuoUsername, zwróć pusty uoKey i (jeśli jest) jako zuoUsername powód błędu
		err_text_start = data_recv.find("err_text=\"")
		err_text_end = data_recv.find("\"", err_text_start + 10)

		if err_text_start != -1 and err_text_end != -1:
			return ("", data_recv[err_text_start + 9:err_text_end + 1])
		
		else:
			return ("", "<serwer nie zwrócił informacji o błędzie>")


def auth_code(authkey):
	f1 = [	29, 43,  7,  5, 52, 58, 30, 59, 26, 35, 35, 49, 45,  4, 22,  4,
		 0,  7,  4, 30, 51, 39, 16,  6, 32, 13, 40, 44, 14, 58, 27, 41,
		52, 33,  9, 30, 30, 52, 16, 45, 43, 18, 27, 52, 40, 52, 10,  8,
		10, 14, 10, 38, 27, 54, 48, 58, 17, 34,  6, 29, 53, 39, 31, 35,
		60, 44, 26, 34, 33, 31, 10, 36, 51, 44, 39, 53,  5, 56	]

	f2 = [	 7, 32, 25, 39, 22, 26, 32, 27, 17, 50, 22, 19, 36, 22, 40, 11,
		41, 10, 10,  2, 10,  8, 44, 40, 51,  7,  8, 39, 34, 52, 52,  4,
		56, 61, 59, 26, 22, 15, 17,  9, 47, 38, 45, 10,  0, 12,  9, 20,
		51, 59, 32, 58, 19, 28, 11, 40,  8, 28,  6,  0, 13, 47, 34, 60,
		 4, 56, 21, 60, 59, 16, 38, 52, 61, 44,  8, 35,  4, 11	]

	f3 = [	60, 30, 12, 34, 33,  7, 15, 29, 16, 20, 46, 25,  8, 31,  4, 48,
		 6, 44, 57, 16, 12, 58, 48, 59, 21, 32,  2, 18, 51,  8, 50, 29,
		58,  6, 24, 34, 11, 23, 57, 43, 59, 50, 10, 56, 27, 32, 12, 59,
		16,  4, 40, 39, 26, 10, 49, 56, 51, 60, 21, 37, 12, 56, 39, 15,
		53, 11, 33, 43, 52, 37, 30, 25, 19, 55,  7, 34, 48, 36	]

	p1 = [	11,  9, 12,  0,  1,  4, 10, 13,  3,  6,  7,  8, 15,  5,  2, 14	]

	p2 = [	 1, 13,  5,  8,  7, 10,  0, 15, 12,  3, 14, 11,  2,  9,  6,  4	]

	ai = []

	for i in range(16):
		c = ord(authkey[i])

		if c > 57:
			if c > 90:
				ai.append(c - 61)

			else:
				ai.append(c - 55)

		else:
			ai.append(c - 48)

	for i in range(16):
		ai[i] = f1[ai[i] + i]

	ai_tmp = []

	for i in range(16):
		ai_tmp.append((ai[i] + ai[p1[i]]) % 62)

	ai = ai_tmp

	for i in range(16):
		ai[i] = f2[ai[i] + i]

	ai_tmp = []

	for i in range(16):
		ai_tmp.append((ai[i] + ai[p2[i]]) % 62)

	ai = ai_tmp

	for i in range(16):
		ai[i] = f3[ai[i] + i]

	authkey = ""

	for i in range(16):
		c = ai[i]

		if c >= 10:
			if c >= 36:
				authkey += chr(c + 61)

			else:
				authkey += chr(c + 55)

		else:
			authkey += chr(c + 48)

	return authkey


def auth_start(sock_client, sock_info, con_id):
	nick = ""
	passwd = ""

	print("%sUstanowiono połączenie: [%s:%d]" % ((get_date_time(con_id), ) + sock_info))
	send_client_info(sock_client, "\x02Połączono z tunelem, oczekiwanie na dane autoryzacji...")

	while nick == "" or passwd == "":
		data_recv = sock_client.recv(1500).decode('iso-8859-2')

		# jeśli jeszcze nie pobrano nicka, sprawdź, czy wysłano NICK
		if nick == "" and "NICK" in data_recv:
			nick = re.findall("NICK (.*?)\r", data_recv)[0]

		# jeśli jeszcze nie pobrano hasła, sprawdź, czy wysłano PASS
		if passwd == "" and "PASS" in data_recv:
			passwd = re.findall("PASS (.*?)\r", data_recv)[0]

	print("%sWykonanie logowania dla: %s" % (get_date_time(con_id), nick))
	send_client_info(sock_client, "Pobrano dane autoryzacji, logowanie do Czatu Onetu...")

	# wykonaj autoryzację HTTP, po której powinniśmy otrzymać uoKey oraz zuoUsername
	(uokey, zuousername) = auth_http(sock_client, con_id, nick, passwd)

	# gdy nie udało się pobrać uoKey, wyświetl zwrócony błąd i zakończ
	if uokey == "":
		print("%sBłąd podczas procesu logowania (brak uoKey), powód: %s" % (get_date_time(con_id), zuousername))
		send_client_info(sock_client, "\x02Błąd podczas procesu logowania (brak uoKey), powód: %s" % zuousername)
		thread_end(sock_client, con_id)

	# pobranie uoKey i zuoUsername umożliwia dalsze logowanie, tym razem do IRC
	print("%sRozpoznany użytkownik na Czacie Onetu: %s" % (get_date_time(con_id), zuousername))
	send_client_info(sock_client, "Rozpoznany użytkownik: \x02%s\r\n\x02authIrcAll..." % zuousername)

	# gniazdo do połączenia z Czatem Onetu
	sock_irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		sock_irc.connect(("czat-app.onet.pl", 5015))

	except socket.error:
		sock_irc.close()
		print("%sNie udało się połączyć z: czat-app.onet.pl" % get_date_time(con_id))
		send_client_info(sock_client, "\x02Nie udało się połączyć z: czat-app.onet.pl")
		thread_end(sock_client, con_id)

	# odbierz z serwera Onetu pierwszą odpowiedź w stylu ":cf1f4.onet NOTICE Auth :*** Looking up your hostname..." i prześlij ją do klienta
	sock_client.send(sock_irc.recv(1500))

	# wyślij do serwera Onetu "NICK nick"
	send_onet_str(sock_client, sock_irc, "NICK %s" % zuousername)

	# pobierz odpowiedź z serwera i w zależności od tego, czy otrzymamy coś w stylu":cf1f4.onet NOTICE Auth :*** Found your hostname (nazwa_hosta)"
	# lub ":cf1f4.onet 433 * ucc_test :Nickname is already in use." to pierwszą z nich prześlij do klienta, a przy drugiej zakończ dalsze działania
	data_recv = recv_onet_str(sock_client, sock_irc)

	if "433" in data_recv and ":Nickname is already in use." in data_recv:
		sock_irc.close()
		print("%s%s jest już w użyciu." % (get_date_time(con_id), zuousername))
		send_client_info(sock_client, "\x02%s\x02 jest już w użyciu." % zuousername)
		thread_end(sock_client, con_id)

	else:
		sock_client.send(data_recv.encode('iso-8859-2'))

	# wyślij do serwera Onetu "AUTHKEY"
	send_onet_str(sock_client, sock_irc, "AUTHKEY")

	# pobierz z serwera Onetu AUTHKEY z kodem
	data_recv = recv_onet_str(sock_client, sock_irc)

	# oblicz nowy kod do wysłania z powrotem
	try:
		authkey = re.findall(":.*?801.*?:(.*?)\r", data_recv)[0]

	except IndexError:
		sock_irc.close()
		print("%sBrak AUTHKEY!" % get_date_time(con_id))
		send_client_info(sock_client, "\x02Brak AUTHKEY!")
		thread_end(sock_client, con_id)

	if len(authkey) != 16:
		sock_irc.close()
		print("%sAUTHKEY nie zawiera oczekiwanych 16 znaków (możliwa zmiana autoryzacji)." % get_date_time(con_id))
		send_client_info(sock_client, "\x02AUTHKEY nie zawiera oczekiwanych 16 znaków (możliwa zmiana autoryzacji).")
		thread_end(sock_client, con_id)

	# wyślij do serwera Onetu obliczony AUTHKEY
	send_onet_str(sock_client, sock_irc, "AUTHKEY %s" % auth_code(authkey))

	# wyślij do serwera Onetu USER z parametrami
	send_onet_str(sock_client, sock_irc, "USER * %s czat-app.onet.pl :%s" % (uokey, tunel_name))

	# dodaj gniazda do zestawu select()
	sock_list = []
	sock_list.append(sock_client)
	sock_list.append(sock_irc)

	# od tej chwili tunel będzie przesyłał dane między serwerem Onetu a klientem, aż do napotkania błędu połączenia po dowolnej stronie
	while True:
		(sock_inp, tmp1, tmp2) = select.select(sock_list, [], [])

		for sock_ready in sock_inp:
			if sock_ready == sock_client:
				try:
					sock_irc.send(sock_ready.recv(1500))

				except socket.error:
					sock_irc.close()
					thread_end(sock_client, con_id)

			if sock_ready == sock_irc:
				try:
					sock_client.send(sock_ready.recv(1500))

				except socket.error:
					sock_irc.close()
					thread_end(sock_client, con_id)


# START
print("Tunel Ucieszony Chat Client v0.1")
print("Copyright (C) 2015 Paweł Ostrowski")
print("Licencja: GNU General Public License v2.0 lub późniejsze wersje\n")

# obsługa sygnału przerwania (Ctrl+C)
signal.signal(signal.SIGINT, signal_break)

# utwórz socket główny tunelu: IPv4, TCP
sock_main = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# spróbuj zbindować port
try:
	sock_main.bind(('', tunel_port))

# gdy się nie uda zbindować portu, pokaż ostrzeżenie
except socket.error:
	print("Nie udało się dowiązać gniazda do: [%s:%d] (port zajęty lub brak uprawnień)" % (socket.gethostbyname(socket.gethostname()), tunel_port))
	sock_main.close()
	exit(2)

# gdy udało się zbindować port
print("Dowiązano gniazdo do: [%s:%d]" % (socket.gethostbyname(socket.gethostname()), tunel_port))
print("Oczekiwanie na połączenie klientów z tunelem...\n")

# nasłuchuj na zbindowanym porcie określoną ilość połączeń (wystarczy jedno, bo każde połączenie będzie osobnym wątkiem)
sock_main.listen(1)

# licznik powtórzonych połączeń klienta z tunelem w ramach sesji tunelu
con_count = 1


# pętla główna
while True:
	# identyfikator odebranego połączenia, w tym miejscu czekamy na zapoczątkowanie połączenia
	(sock_main_c, sock_main_a) = sock_main.accept();

	# połączenie zapoczątkowane, wykonaj autoryzację
	thread.start_new_thread(auth_start, (sock_main_c, sock_main_a, con_count))

	# inkrementacja licznika powtórzonych połączeń
	con_count += 1
