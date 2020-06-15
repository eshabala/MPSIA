import requests
import urllib3 
from bs4 import BeautifulSoup as BS # html парсер
import json
import os, errno, sys
from jinja2 import Template # шаблонизатор для генерации репортов
import codecs # чтение utf-8
import datetime, time
from MPSEmailSender import EmailSender

import pdfkit
#path_wkhtmltopdf = u'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe'
#config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
options = {
    'zoom': '1.5',
    'page-size': 'Letter',
    'margin-top': '0',
    'margin-right': '0',
    'margin-bottom': '0',
    'margin-left': '0',
    'quiet': '',
    }

class MPSNewIncidentAlert: # работоспособность проверялась на MAXPATROL SIEM 21.0.0
    
    def __init__(self, HOSTADDR, USER, PASSWORD, SELF_SIGNED_CERT="skip", USER_HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101 Firefox/73.0', 'Content-Type': 'application/json', 'Accept': 'text/plain', 'Content-Encoding': 'utf-8'}):
        
        self.HOSTADDR = HOSTADDR # Адрес MAXPATROL SIEM (стандартный порт, не указывается)
        self.USER = USER # Пользователь, который имеет доступ к событиям и инцидентам
        self.PASSWORD = PASSWORD # Пароль пользователя
        self.SELF_SIGNED_CERT = SELF_SIGNED_CERT # SELF_SIGNED_CERT={None,"skip", ('/path/server.crt', '/path/key') или SELF_SIGNED_CERT='/wrong_path/server.pem') Если сертификат самоподписанный, необходимо указать skip, иначе будет отключена прверка сертификата.
        self.USER_HEADERS = USER_HEADERS # Заголовки, стандартно заданы.
        self.prepare() # Подготовка к осуществлению соединения с MAXPATROL SIEM
        self.auth() # Авторизация в MAXPATROL SIEM
        self.get_incidents() # Получение инцидентов
        #self.gen_report() # Генерация отчета по инциденту
        print('alert')
    def prepare(self): # Подготовка к осуществлению соединения с MAXPATROL SIEM
        
        if self.SELF_SIGNED_CERT == "skip": # Если выбран пропуск валидации сертификата
            urllib3.disable_warnings() # Отключение ошибки проверки сертификата
            self.VERIFY = False # Отключения  проверки сертификата
            self.SELF_SIGNED_CERT = None
        else:
            self.VERIFY = True # Включение проверки сертификата
    
    def auth(self):
        
        self.log_report("IПопытка авторизации на сервере [%s]" % self.HOSTADDR)
        
        AUTH_JSON = {"authType":0, "username":self.USER, "password":self.PASSWORD, "rememberLogin":"true"}
        
        t_USER_HEADERS = self.USER_HEADERS.copy() # Локальная копися заголовков
        
        try:
            self.SESSION =  requests.Session() # инициализация хранение сессий и кук
            self.SESSION.headers = t_USER_HEADERS # заголовки
            self.SESSION.post(self.HOSTADDR+":3334/ui/login", json=AUTH_JSON, verify=self.VERIFY, cert=self.SELF_SIGNED_CERT, allow_redirects=True) # POST с логином и паролем, получение первых кук
            response = self.SESSION.get(self.HOSTADDR+"/account/login?returnUrl=%2F%23%2Fauthorization%2Flanding", verify=self.VERIFY, cert=self.SELF_SIGNED_CERT, allow_redirects=True) # получение кук и данных ответа
            
            pars_html = BS(response.text, 'html.parser') # инициализируем html парсер
            
            POST_VAR_1 = { # переменные из формы 1 для POST запроса
                'code' : pars_html.find('input', {'name':'code'})['value'],
                'id_token' : pars_html.find('input', {'name':'id_token'})['value'],
                'scope' : pars_html.find('input', {'name':'scope'})['value'],
                'state' : pars_html.find('input', {'name':'state'})['value'],
                'session_state' : pars_html.find('input', {'name':'session_state'})['value']  
            }

            t_USER_HEADERS['Content-Type'] = "application/x-www-form-urlencoded" # изменение content-type
            self.SESSION.headers = t_USER_HEADERS # специальные заголовки

            response = self.SESSION.post(self.HOSTADDR+":3333/core", data = POST_VAR_1, verify=self.VERIFY, cert=self.SELF_SIGNED_CERT, allow_redirects=True)  # получение кук и данных ответа
            
            pars_html = BS(response.text, 'html.parser') # инициализация парсера
    
            POST_VAR_2 = { # переменные из формы 2 для POST запроса
                'wa' : pars_html.find('input', {'name':'wa'})['value'],
                'wresult' : pars_html.find('input', {'name':'wresult'})['value'],
                'wctx' : pars_html.find('input', {'name':'wctx'})['value'] 
            }
                    
            self.SESSION.post(self.HOSTADDR, data = POST_VAR_2, verify=False, allow_redirects=True) # получение последних кук
            # АВТОРИЗАЦИЯ ПРОЙДЕНА, МОЖНО ВЫПОЛНЯТЬ ЗАПРОСЫ К API
            self.log_report("SВыполнена авторизации на сервере [%s]." % self.HOSTADDR)
            
        except:
            self.log_report("FНе могу соедениться с сервером [%s] ..." % self.HOSTADDR)
            self.log_report("XВыполнение остановлено.")
            #print("Не могу соедениться с сервером [%s] ..." % self.HOSTADDR)
            self.SESSION.close()
            sys.exit(0)
            
    def get_incidents(self):
        
        self.log_report("IПолучение списка всех инцидентов с даты последнего известного.")
        
        self.SESSION.headers = self.USER_HEADERS.copy() # установка стандартного заголовка
        
        with open(".last-update-unix-time", "r") as f_last_update_time: # файл с последней датой обновления
            last_update_time = f_last_update_time.read() # читение последней даты обновления
            
        #with open(".last-update-unix-time", "w") as f_last_update_time: # запись текущей даты в файл
            #f_last_update_time.write(str(int(time.time())))
            
        with open("templates/all-incidents.json", "r") as read_file: # чтение шаблона для POST запроса
             POST_all_incidents = json.load(read_file)

        POST_all_incidents['timeFrom'] = int(last_update_time) # изменение даты в запросе на последнюю дату обновления
        
        ### Получение вех инцидентов ###
        all_incidents_from_time = self.SESSION.post(self.HOSTADDR+"/api/v2/incidents/", json=POST_all_incidents, verify=self.VERIFY, cert=self.SELF_SIGNED_CERT) # получаем все инциденты по времени
        all_incidents_from_time = json.loads(all_incidents_from_time.text) # получение в виде json

        if int(all_incidents_from_time['totalItems']) == 0: # если нет новых инцидентов
            self.log_report("XНовых инциднтов не обнаружено.")
            self.SESSION.close()
            sys.exit(0)
        
        for incident in all_incidents_from_time['incidents']: # для каждого инцидента

            last_incident_f = open(".indexDB", "r") # чтение индексов прошлых инцидентов
            last_incidents = last_incident_f.read().splitlines() # загрузка файла в list
            last_incident_f.close() # закрытие файла с БД
            
            if incident['id'] in last_incidents: # если инцидент уже рассматривался
                self.log_report("IПовторный индидент [%s] обнаружен, отчет не генерируется!" % incident['id'])
                continue
            
            self.log_report("IРазбор инцидента [%s]" % incident['id'])
    
            file_name = "incidents/"+incident['id']+"/incident.json" # файл с текущим инцидентом
    
            if not os.path.exists(os.path.dirname(file_name)): # если нет пути
                try:
                    os.makedirs(os.path.dirname(file_name)) # сделать директорию
                except OSError as exc: # Guard against race condition
                    if exc.errno != errno.EEXIST:
                        raise
                    
            file = open(file_name, "w") 
            json.dump(incident, file, indent=4, sort_keys=True) # дамп в файл в json виде
            file.close()
            
            self.log_report("IПолечение деталей инцидента")
         
            ### Полечение деталей инцидента ###
            
            incident_detail = self.SESSION.get(self.HOSTADDR+"/api/incidents/"+incident['id'], verify=self.VERIFY, cert=self.SELF_SIGNED_CERT)
    
            file_name = "incidents/"+incident['id']+"/incident_detail.json"
    
            incident_detail = json.loads(incident_detail.text) # считывание json
    
            file = open(file_name, "w")
            json.dump(incident_detail, file, indent=4, sort_keys=True) # запись в файл в формате json
            file.close()
            
            self.log_report("IПолечение списка связанных событий")
            
            ### Полечение списка связанных событий ###
            
            incident_events = self.SESSION.get(self.HOSTADDR+"/api/incidents/"+incident['id']+"/events/", verify=self.VERIFY, cert=self.SELF_SIGNED_CERT)
    
            file_name = "incidents/"+incident['id']+"/incident_events.json"
    
            incident_events = json.loads(incident_events.text) # считывание json
    
            file = open(file_name, "w")
            json.dump(incident_events, file, indent=4, sort_keys=True) # запись в файл в формате json
            file.close()
            
            self.log_report("IОписание всех связанных событий")
            ### Описание всех связанных событий  ###
            
            with open("templates/incident-events-detail.json", "r") as read_file: # читаем шаблон для POST запроса
        
                POST_all_incidents_events = json.load(read_file)
    
            incident_event_details = self.SESSION.post(self.HOSTADDR+"/api/events/v2/events/?incidentId="+incident['id']+"&limit=100&offset=0", json=POST_all_incidents_events, verify=self.VERIFY, cert=self.SELF_SIGNED_CERT) # получение event с деталями
    
            file_name = "incidents/"+incident['id']+"/incident_events_detail.json" # выбор файлов для хранения данных event'ов
    
            incident_event_details = json.loads(incident_event_details.text) # загрузка в json данных из запроса
    
            file = open(file_name, "w")
            json.dump(incident_event_details, file, indent=4, sort_keys=True) # запись в файл json
            file.close()
            
            incident_time = int(incident['created']) # время текущего инцидента
            if incident_time > int(last_update_time): # если инцидент был позже, чем текущее время last_update_time
                last_update_time = str(incident_time) # то изменяется текущее время
            
            self.log_report("IГенерация отчета по инциденту")
            self.gen_report(incident, incident_detail, incident_events, incident_event_details) 
        
        
        with open(".last-update-unix-time", "w") as f_last_update_time: # запись текущей даты в файл
            f_last_update_time.write(str(int(last_update_time)+1))
        self.SESSION.close()
        
        self.dbindex(all_incidents_from_time['incidents']) # запись в БД
        self.gen_inc_list(last_update_time)
        self.log_report("SСписок инцидентов обновлен, отчеты сгенерированы.")
        
    def dbindex(self, all_incidents): # хранение и добавление в файловой базе данных  инцидентов
        index = open(".indexDB", "r") # чтение индексов прошлых инцидентов
        lines = index.read().splitlines() # загрузка файла в list
        index.close() # закрытие файла с БД
        
        index = open(".indexDB", "a") # открытие файла на дозапись
        data = codecs.open(".indexDB_data", "a", "utf-8") # открытие файла на дозапись
        all_incidents.reverse() # разворот листа
        for inc in all_incidents: # 
            if inc['id'] not in lines: # если инцидента еще нет в бд
                index.write(inc['id']+"\n") # дозапись в файл
                data.write(str(inc['id'])+":"+str(inc['key'])+":"+str(inc['category'])+":"+str(inc['status'])+":"+str(inc['name'])+":"+str(inc['assigned']['firstName'])+":"+str(inc['assigned']['lastName'])+"\n") # дозапись в файл       
        index.close()
        data.close()
        
    def normaltime(self, timestamp): # нормализация времени из UNIX в стандартный вид
        dt = datetime.datetime.fromtimestamp(timestamp)
        return str(dt.strftime('%Y-%m-%d %H:%M:%S'))
    
    def gen_inc_list(self, last_update_time): # генерация списка инцидентов
        inclist_template_file = codecs.open("templates/html/list.html", "r", "utf-8") # открытие шаблона отчета на чтение
        inclist_template = inclist_template_file.read() # чтение шаблона
        
        data = codecs.open(".indexDB_data", "r", "utf-8") # открытие файла с БД на чтение
        lines = data.read().splitlines() # загрузка файла в list
        #lines.remove(' ');
        try:
            lines.remove(' ')
        except:
            pass
        lines.reverse() # разворот листа (новые инциденты будут в начале списка)
        for i in range(0, len(lines)):
            lines[i] = lines[i].split(":") # разделение на поля по разделителю
        data.close() # закрытие файла с БД
        
        template = Template(inclist_template) # преобразование в шаблон
        t = self.normaltime(int(last_update_time)) # нормализация времени
        export = template.render(incidents=lines, dblast_update_time=t) # рендер с параметрами
        inc_list = codecs.open("reports/index.html", "w", "utf-8") # сохранение отчетов
        inc_list.write(export) # запись
        inc_list.close()
        
        
        
    def gen_report(self, i_json, i_json_detail, i_json_events, i_json_events_detail): # генерация отчетов по инцидентам и связанным событиям
        """ генерировать отчет в html файл, надо разработать структуру файла (таблицы)
            как-то связать файл отчета с общим файлом, в котором лежат 
        """ 
        
        i_json_detail['created'] = self.normaltime(i_json_detail['created']) # нормализуется время
        
        
        report_template_file = codecs.open("templates/html/report.html", "r", "utf-8") # открытие шаблона отчета на чтение
        report_template = report_template_file.read() # чтение шаблона
        
        template = Template(report_template) # преобразование 
        export = template.render(inc=i_json,  inc_detail=i_json_detail, inc_events=i_json_events, inc_events_detail=i_json_events_detail) # рендер с параметрами
        
        report = codecs.open("incidents/"+i_json['id']+"/report.html", "w", "utf-8") # сохранение отчетов
        report.write(export) # запись
        
        report_template_file.close() # закрытие файлов
        report.close()
        #try:
        pdfkit.from_file("incidents/"+i_json['id']+"/report.html", "incidents/"+i_json['id']+"/report.pdf", options=options)
        #except:
            #self.log_report("EНе возможно создать отчет в формате pdf по инциденту "+i_json['key'])
            
        try:
            EmailSender("message","sendto", i_json)
        except:
            self.log_report("EНе возможно отправить оповещение на email по инциденту "+i_json['key'])
        

    def log_report(self, state="FНеизвестная ошибка"):
        log_error_list = {"E": "ОШИБКА", "I":"ИНФО", "F":"ФАТАЛЬНАЯ ОШИБКА", "S":"ВЫПОЛНЕНО", "X":"ЗАВЕРШЕНО"} # список кодов ошибок
        if state[0] in log_error_list: # проверка существования кода
            logfile = codecs.open("log.txt", "a", "utf-8") # открытие файла логов для записи
            event_time = self.normaltime(time.time()) # текущее время в нормальном представлении
            logfile.write("["+event_time+"] "+log_error_list[state[0]]+": "+state[1:]+"\n") # заись в файл
            logfile.close()
        
