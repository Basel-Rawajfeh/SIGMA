#Import the required Libraries
import sqlite3
import webbrowser

# from tkinter import filedialog 
import os
import requests
import socket
# scan a range of port numbers on a host concurrently
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Environment, FileSystemLoader
import pdfkit
import time
import customtkinter
from tkinter import *
from tkinter import ttk
# what is the date and time?
from datetime import datetime
from PIL import Image
now = datetime.now()
# dd/mm/YY H:M:S
dt_string = now.strftime("%d/%m/%Y %H:%M")

conn = sqlite3.connect('vulnerabilities_db.sqlite') 
c = conn.cursor()

#Create an instance of Tkinter frame
win= customtkinter.CTk()

#Set the geometry of Tkinter frame
win.title('SIGMA')
win.geometry("800x800")
tab_control = ttk.Notebook(win)

tab1 = customtkinter.CTkFrame(tab_control)

tab2 = customtkinter.CTkFrame(tab_control)

tab_control.add(tab1, text='Scan')

tab_control.add(tab2, text='About SIGMA')




# add an image using the CTkImage class
image = customtkinter.CTkImage(light_image=Image.open("logo2.png"),dark_image=Image.open("logo2.png"))


label = customtkinter.CTkLabel(tab2, image=image,text="""
Developed by:                   

Basel Rawajfeh                   

Laith Hani                   

Mohammad Waleed                   

Omar Nabeal                   


""",compound="right",font=("Arial", 12))
label.image = image
label.grid(row=0,column=0,columnspan=2)

# create a big text box
text_box = customtkinter.CTkTextbox(tab2) 


# center the text

text_box.grid(row=2,column=0,columnspan=2)
text_box.insert(END, """SIGMA is a web application security scanner that can scan a website for common vulnerabilities and generate a report for the user. It is a free and open source tool that can be used by anyone to scan their websites for vulnerabilities. SIGMA is developed by a group of students from the University of Jordan as a project for the course of Information Security. The tool is developed using Python and SQLite. The tool is still under development and more features will be added in the future. The tool is developed by the following students: Basel Rawajfeh, Laith Hani, Mohammad Waleed, and Omar Nabeal. The tool is developed under the supervision of Dr. Mohammad Al-Sulaiman. The tool is developed as a project for the course of Information Security. The tool is developed using Python and SQLite. The tool is still under development and more features will be added in the future. The tool is developed by the following students: Basel Rawajfeh, Laith Hani, Mohammad Waleed, and Omar Nabeal. The tool is developed under the supervision of Dr. Mohammad Al-Sulaiman. The tool is developed as a project for the course of Information Security. The tool is developed using Python and SQLite. The tool is still under development and more features will be added in the future. The tool is developed by the following students: Basel Rawajfeh, Laith Hani, Mohammad Waleed, and Omar Nabeal. The tool is developed under the supervision of Dr. Mohammad Al-Sulaiman. The tool is developed as a project for the course of Information Security. The tool is developed using Python and SQLite. The tool is still under development and more features will be added in the future. The tool is developed by the following students: Basel Rawajfeh, Laith Hani, Mohammad Waleed, and Omar Nabeal. The tool is developed under the supervision of Dr. Mohammad Al-Sulaiman. The tool is developed as a project for the course of Information Security. The tool is developed using Python and SQLite. The tool is still under development and more features will be added in the future. The tool is developed by the following students: Basel Rawajfeh, Laith Hani, Mohammad Waleed, and Omar Nabeal. The tool is developed under the supervision of Dr. Mohammad Al-Sulaiman. The tool is developed as a project""")
# text_box.pack(expand=1, fill='both')

# label.pack(expand=1, fill='both')




tab_control.pack(expand=1, fill='both')
port_list_id = []
vul_list_id = []
portslist = []  
# define ip variable
domain = ""
# returns True if a connection can be made, False otherwise


def main():
   global entry
   domain = entry.get()
   if domain.startswith("http://"):
        domain
   elif domain.startswith("https://"):
        domain
   elif not domain.startswith("http://") or not domain.startswith("https://"):
        domain = "http://"+ domain
   

   # change the label text 
   if entry.get() == "":

     label.configure(text="Please enter an URL")
     #   change label color
     label.configure(fg="red")
     # change the label size  
     label.configure(font=("Arial", 12))
    
   else:  
          
          headers = requests.get(domain).headers
          
          def cookiesscan(domain):
               # check if cookies are secure
                cookies = requests.get(domain).cookies
                for cookie in cookies:
                    if cookie.secure == False:
                         vul_list_id.append(24)
                         break
                    else:
                         pass
               # check if cookies are httpOnly
                for cookie in cookies:
                    if cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'):
                         pass
                    else:
                         vul_list_id.append(25)
                         break             
                             
              
          def scan_xframe(self):
               """X-Frame-Options should be set to DENY or SAMEORIGIN"""
               try:
                    if "deny" in self.headers["X-Frame-Options"].lower():
                         disable()
                    elif "sameorigin" in self.headers["X-Frame-Options"].lower():
                         disable()
                    else:
                         vul_list_id.append(0)
               except KeyError:
                    vul_list_id.append(0)
          scan_xframe(requests.get(domain))
          
          if 'X-XSS-Protection' in headers:
               disable()
          else: 
               vul_list_id.append(1)
               disable()
               
                 
          def scan_nosniff(self):
               """X-Content-Type-Options should be set to 'nosniff' """
               try:
                    if self.headers["X-Content-Type-Options"].lower() == "nosniff":
                         disable()
                    else:
                         vul_list_id.append(2)
               except KeyError:
                    vul_list_id.append(2)
          scan_nosniff(requests.get(domain))

          if 'Content-Security-Policy' in headers:
               disable()
          else: 
               vul_list_id.append(3)
               disable()

               
          if 'Cache-Control' in headers:
               disable()
          else: 
               vul_list_id.append(4)
               disable()    
                    
          if 'X-Permitted-Cross-Domain-Policies' in headers:
               vul_list_id.append(5)
               disable()
          else: 
               
               disable()
                         
          if 'Public-Key-Pins' in headers:
               vul_list_id.append(7)
               disable()
          else: 
               disable()

          if 'Referrer-Policy' in headers:
               disable()
          else: 
               vul_list_id.append(8)
               disable()

          def scan_hsts(self):
               """config failure if HSTS header is not present"""
               try:
                    if self.headers["Strict-Transport-Security"]:
                         disable()
               except KeyError:
                    vul_list_id.append(7)
                    
          scan_hsts(requests.get(domain))
          cookiesscan(domain)  
          for i in range(25):
               time.sleep(0.01)
               progress['value'] += 1
               win.update_idletasks()  
          progress['value'] = 0  

# define host and port numbers to scan
def scan_ports():
     # wait for the user to enter a domain name
     for i in range(25):
          time.sleep(0.001)
          progress['value'] += 1
          win.update_idletasks()    
     if entry.get() == "":
       label.configure(text="Please enter an URL")
        #   change label color
       label.configure(fg="red")
       label.configure(font=("Arial", 12))
     else:
          domain = entry.get()
          HOST = f'{domain}'
          PORTS = [21,22,23,25,53,69,80,137,139,443,445,3306,3389,8080,8443]
          # PORTS = range(65535)
          # test theportlist
          port_scan(HOST, PORTS)

def test_port_number(host, port):
    
    # create and configure the socket
    with socket(AF_INET, SOCK_STREAM) as sock:
        # set a timeout of a few seconds
        sock.settimeout(3)
        # connecting may fail
        try:
            # attempt to connect
            sock.connect((host, port))
            # a successful connection was made
            return True
        except:
            # ignore the failure
            return False
         
# scan port numbers on a host
def port_scan(host, ports):
    
    for i in range(25):
          time.sleep(0.001)
          progress['value'] += 1
          win.update_idletasks()    
    print(f'Scanning {host}...')
#     create the thread pool
    with ThreadPoolExecutor(len(ports)) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, [host]*len(ports), ports)    
        # report results in order
        for port,is_open in zip(ports,results):
            if is_open:
               # add the port to the list
                portslist.append(port)
    print(f'Open ports on {host}: {portslist}')           
    for x in portslist:
                    
                    if x == 21:
                         port_list_id.append(9)
                                        
                    if x == 22:
                         port_list_id.append(10)
          
                    if x == 23:
                         port_list_id.append(11)
          
                    if x == 25:
                         port_list_id.append(12)
          
                    if x == 53:
                         port_list_id.append(13)
          
                    if x == 69:
                         port_list_id.append(14)
          
                    if x == 8080 :  
                         port_list_id.append(15)
          
                    if x == 137:
                         port_list_id.append(16)
          
                    if x == 3306:
                         port_list_id.append(17)
          
                    if x == 3389:
                         port_list_id.append(18)
          
                    if x == 8443:
                         port_list_id.append(19)
          
                    if x == 443:
                         port_list_id.append(20)
          
                    if x == 80:
                         port_list_id.append(21)
          
                    if x == 139:
                         port_list_id.append(22)
          
                    if x == 445:
                         port_list_id.append(23)
                    
    for i in range(25):
          time.sleep(0.001)
          progress['value'] += 1
          win.update_idletasks()      
           
    
def disable():
        scan.configure(state=customtkinter.DISABLED)


def reset():
        # resets the button to normal
        scan.configure(state=customtkinter.NORMAL)
        # clears the list
        vul_list_id.clear()
        portslist.clear()
        # clears the label
        label.configure(text="Enter the URL to scan")
        label.configure(fg="black")
        label.configure(font=("Arial", 12))
        # clears the entry
        entry.delete(0,customtkinter.END)
        entry.focus()
          # clear the port list
        port_list_id.clear()



        

def report():      

        # an array to store the vulnerabilities

        vul_list = []

        sev_list = []

        sum_list = []

        imp_list = []

        rem_list = []

        color_list = []

        port_list = []

        psum_list = []

        service_list = []

        protocol_list = []

        pimpact_list = []

        def vuln():
         # loops through the vul_list_id list and appends the vul_list with the corresponding vulnerability
                global id
                for id in vul_list_id:
           
                        c.execute(f'''
                                SELECT vuln_name FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        vul_list.append(c.fetchone()[0])
                        c.execute(f'''
                                SELECT summary FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        sum_list.append(c.fetchone()[0]) 

                        c.execute(f'''
                                SELECT impact FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        imp_list.append(c.fetchone()[0]) 
                        c.execute(f'''
                                SELECT remediation FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        rem_list.append(c.fetchone()[0])
                        c.execute(f'''
                                SELECT severity FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        sev_list.append(c.fetchone()[0])
                        c.execute(f'''
                                   SELECT color FROM vulnerability WHERE vuln_id = {id+1}
                                   ''')
                        color_list.append(c.fetchone()[0])
                        

                for x in port_list_id:
                        c.execute(f'''
                                SELECT vuln_name FROM vulnerability WHERE vuln_id = {x+1}
                                ''')
                        port_list.append(c.fetchone()[0])
                        
                        c.execute(f'''
                                   SELECT summary FROM vulnerability WHERE vuln_id = {x+1}
                                   ''')
                        psum_list.append(c.fetchone()[0])

                        c.execute(f'''
                                   SELECT impact FROM vulnerability WHERE vuln_id = {x+1}
                                   ''')
                        protocol_list.append(c.fetchone()[0])

                        c.execute(f'''
                                   SELECT remediation FROM vulnerability WHERE vuln_id = {x+1} 
                                   ''')
                        pimpact_list.append(c.fetchone()[0])

                        c.execute(f'''
                                   SELECT severity FROM vulnerability WHERE vuln_id = {x+1}
                                   ''')
                        service_list.append(c.fetchone()[0])
                    
        vuln()
        
        num_vul = len(vul_list) 
        num_ports = len(port_list)
        vulnerabilities = []
        portsx = []
        # add the rest of the vulnerabilities
        for i in range(num_vul):
                vulnerabilities.append({"name": vul_list[i],"summary": sum_list[i],"impact": imp_list[i],"remediation": rem_list[i],"severity": sev_list[i],"color": color_list[i]})

        for i in range(num_ports):
                    portsx.append({"name": port_list[i],"summary": psum_list[i],"protocol": protocol_list[i],"impact": pimpact_list[i],"service": service_list[i]})

        environment = Environment(loader=FileSystemLoader("."))

        results_template= environment.get_template("index.html")
        fileName= "Report.html"
        context = {
        "vulnerabilities": vulnerabilities,
        "ports":portsx,
        "date":f"{datetime.now():%d-%m-%Y %H:%M}"}
        

        with open(fileName, mode="w", encoding="utf-8") as results:
                results.write(results_template.render(context))

                print("... wrote HTML Report")
                
                webbrowser.open(fileName)
        
def downloadPdf():

        # an array to store the vulnerabilities

        vul_list = []

        sev_list = []

        sum_list = []

        imp_list = []

        rem_list = []

        color_list = []

        port_list = []

        psum_list = []

        service_list = []

        protocol_list = []

        pimpact_list = []

        def vuln():
         # loops through the vul_list_id list and appends the vul_list with the corresponding vulnerability
                global id
                for id in vul_list_id:
           
                        c.execute(f'''
                                SELECT vuln_name FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        vul_list.append(c.fetchone()[0])
                        c.execute(f'''
                                SELECT summary FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        sum_list.append(c.fetchone()[0]) 

                        c.execute(f'''
                                SELECT impact FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        imp_list.append(c.fetchone()[0]) 
                        c.execute(f'''
                                SELECT remediation FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        rem_list.append(c.fetchone()[0])
                        c.execute(f'''
                                SELECT severity FROM vulnerability WHERE vuln_id = {id+1}
                                ''')
                        
                        sev_list.append(c.fetchone()[0])
                        c.execute(f'''
                                   SELECT color FROM vulnerability WHERE vuln_id = {id+1}
                                   ''')
                        color_list.append(c.fetchone()[0])
                        conn.commit()

                for x in port_list_id:
                        c.execute(f'''
                                SELECT vuln_name FROM vulnerability WHERE vuln_id = {x+1}
                                ''')
                        port_list.append(c.fetchone()[0])
                        
                        c.execute(f'''
                                   SELECT summary FROM vulnerability WHERE vuln_id = {x+1}
                                   ''')
                        psum_list.append(c.fetchone()[0])

                        c.execute(f'''
                                   SELECT impact FROM vulnerability WHERE vuln_id = {x+1}
                                   ''')
                        protocol_list.append(c.fetchone()[0])

                        c.execute(f'''
                                   SELECT remediation FROM vulnerability WHERE vuln_id = {x+1} 
                                   ''')
                        pimpact_list.append(c.fetchone()[0])

                        c.execute(f'''
                                   SELECT severity FROM vulnerability WHERE vuln_id = {x+1}
                                   ''')
                        service_list.append(c.fetchone()[0])
                        conn.commit()
           
        vuln()
        
        num_vul = len(vul_list) 
        num_ports = len(port_list)
        vulnerabilities = []
        portsx = []
        # add the rest of the vulnerabilities
        for i in range(num_vul):
                vulnerabilities.append({"name": vul_list[i],"summary": sum_list[i],"impact": imp_list[i],"remediation": rem_list[i],"severity": sev_list[i],"color": color_list[i]})
                
        for i in range(num_ports):
                    portsx.append({"name": port_list[i],"summary": psum_list[i],"protocol": protocol_list[i],"impact": pimpact_list[i],"service": service_list[i]})

        environment = Environment(loader=FileSystemLoader("."))

        results_template= environment.get_template("index.html")
        fileName= "Report.html"
        context = {
        "vulnerabilities": vulnerabilities,
        "ports":portsx,
        "date":f"{datetime.now():%d-%m-%Y %H:%M}"}

        with open(fileName, mode="w", encoding="utf-8") as results:
                results.write(results_template.render(context))

                print("... wrote PDF Report")
            
     #Define path to wkhtmltopdf.exe
        path_to_wkhtmltopdf = r'D:\Learning\Project\Tool\wkhtmltox\bin\wkhtmltopdf.exe'

     #Define path to HTML file
        path_to_file = 'Report.html'

     #Point pdfkit configuration to wkhtmltopdf.exe
        config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

     #set paper size to b0
        options = {
          'enable-local-file-access': True     ,
          'page-size'               : 'A2'     ,
          }
     #Convert HTML file to PDF  
        pdfkit.from_file(path_to_file, output_path='Report.pdf', configuration=config, options=options)

          #Open PDF file
        os.startfile('Report.pdf')    

# create a frame
frame = customtkinter.CTkFrame(tab1)
frame.pack(pady=20)

# fit a logo to the win
logo = PhotoImage(file="logo.png")
logo_label = customtkinter.CTkLabel(frame,image=logo, width=700, height=500)
logo_label.grid(row=1, column=0,columnspan=3,pady=20)


# create a label
label = customtkinter.CTkLabel(frame, text="Enter a website to scan")
label.configure(font=("Arial", 12))
label.grid(row=2, column=0)

# create an entry
entry = customtkinter.CTkEntry(frame, font=("Helvetica", 24))
entry.focus()
entry.grid(row=2, column=1)

scan=customtkinter.CTkButton(frame, text= "Scan",width= 15,command= lambda: [scan_ports(), main()])
scan.grid(row=2, column=2, padx=10, pady=10)
resetb=customtkinter.CTkButton(frame, text="Reset",width= 15, command=reset)
resetb.grid(row=3, column=2, padx=10, pady=10)

reportb=customtkinter.CTkButton(frame, text="HTML Report",width= 15, command=report)
reportb.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

pdf=customtkinter.CTkButton(frame, text="PDF Report",width= 15, command=downloadPdf)
pdf.grid(row=3, column=1, columnspan=2, padx=10, pady=10)

close=customtkinter.CTkButton(frame, text="Close", command=win.destroy,width= 15)
close.grid(row=4, column=2, padx=10, pady=10)

progress = customtkinter.CTkProgressBar(frame, mode='determinate')
progress.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

win.mainloop()
conn.close()






