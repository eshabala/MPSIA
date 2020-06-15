import smtplib

from string import Template

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase 
from email import encoders


class EmailSender():
    
    def __init__(self, template, address_book, incident):
        """
        В конструктор необходимо передать:
            1) имя шаблона сообщения (вариативное поле PERSON_NAME)
            2) имя адрессной книги
            3) пусть к файлу, который будет передаваться в attachment
            4) имя файла, которое будет присвоено и будет отображаться в письме
        
        """
        self.SENDER_EMAIL = 'email@mail.com' # email адрес отправителя
        self.SENDER_PASSWORD = 'password' # пароль отправителя
        self.SENDER_SMTP = 'smtp.mail.com' # SMTP сервер отправителя
        self.SENDER_SMTP_PORT = 587 # порт SMTP сервера отправителя
        
        self.PORTAL_INC='http://IP/incidents/'+incident['id']+"/report.html"
        self.PORTAL_ADDR='http://IP/reports'
        
        
        names, emails = self.get_contacts('templates/'+address_book+'.txt') # чтение контактов
        message_template = self.read_template('templates/'+template+'.txt') # чтение шаблона письма

        # подключение к SMTP серверу
        s = smtplib.SMTP(host=self.SENDER_SMTP, port=self.SENDER_SMTP_PORT)
        s.starttls()
        s.login(self.SENDER_EMAIL, self.SENDER_PASSWORD)

        # для каждого контакта из адресной книги отправляем письмо:
        for name, email in zip(names, emails):
            msg = MIMEMultipart()       # создание сообщения

            # вводится актуальное имя из контактов
            message = message_template.substitute(PERSON_NAME=name.title(), PORTAL_INC=self.PORTAL_INC, PORTAL_ADDR=self.PORTAL_ADDR)

            #print(message)

            # Параметры сообщения
            msg['From']=self.SENDER_EMAIL
            msg['To']=email
            msg['Subject']="[НОВЫЙ ИНЦИДЕНТ] "+incident['key']
        
            # открытие файла в бинарном виде для дальнейшей отправки
            filename = incident['key']+".pdf"
            attachment = open("incidents/"+incident['id']+"/report.pdf", "rb") 
  
            payload = MIMEBase('application', 'octet-stream')  # инициализируем MIMEBase 
            payload.set_payload((attachment).read()) # загрузка в MIMEBase как пэйлоад
            encoders.encode_base64(payload) # кодирование в  base64 
            payload.add_header('Content-Disposition', "attachment; filename= %s" % filename) # добавление заголовка
  
            msg.attach(payload) # прикрепление пэйлоада к сообщению
            msg.attach(MIMEText(message, 'plain')) # добавление к письму тела
            s.send_message(msg) # отправление сообщения
        
            del msg # удаление сообщения
        
        s.quit() # Закрытие сессии
    
    
    def get_contacts(self, filename):
        """
        Возвращает 2 списка Фамилия+Инициалы(Имя) и email адрес
        прочитанные из файла с именем filename
        """
        names = []
        emails = []
        with open(filename, mode='r', encoding='utf-8') as contacts_file:
            for a_contact in contacts_file:
                names.append(a_contact.split()[0]+" "+a_contact.split()[1])
                emails.append(a_contact.split()[2])
        return names, emails

    def read_template(self, filename):
        """
        Возвращает объект шаблона сообщения
        """
        with open(filename, 'r', encoding='utf-8') as template_file:
            template_file_content = template_file.read()
            
        return Template(template_file_content)

    
