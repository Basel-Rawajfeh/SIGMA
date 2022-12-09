#Import the required Libraries
import sqlite3
import webbrowser
from tkinter import *
from tkinter import ttk
# from tkinter import filedialog 
import os
import requests
import socket
# scan a range of port numbers on a host concurrently
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from concurrent.futures import ThreadPoolExecutor
import threading
from jinja2 import Environment, FileSystemLoader
import pdfkit
import time



# what is the date and time?
from datetime import datetime
now = datetime.now()
# dd/mm/YY H:M:S
dt_string = now.strftime("%d/%m/%Y %H:%M")




conn = sqlite3.connect('vulnerabilities_db.sqlite') 
c = conn.cursor()

#Create an instance of Tkinter frame
win= Tk()

#Set the geometry of Tkinter frame
win.title('SIGMA')
win.geometry("800x800")
tab_control = ttk.Notebook(win)

tab1 = ttk.Frame(tab_control)

tab2 = ttk.Frame(tab_control)

tab_control.add(tab1, text='Scan')

tab_control.add(tab2, text='About SIGMA')

# create a big text box
text_box = Message(tab2,width=600,text="""Data is very exposed nowadays and year by year the technology is getting more advanced which creates new security threat that demand new security solutions.
SIGMA is tool which has been developed by a group of students using different research and resources that discover and determine the vulnerabilities and weaknesses in websites by scanning the web applications URLs to find some of  the well-known vulnerabilities in both the headers and the website itself . which will provide to users instructions about the safe websites and whether the targeted website is vulnerable or secure .aiming to improve web applications by giving the website's users privacy and security as well as preventing the leakage of their personal data.
""", pady=20)
text_box.grid(row=0,column=0)





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
                         print("Cookie is not secure")
                         break
                    else:
                         print("Cookie is secure")
                         break
               # check if cookies are httpOnly
                for cookie in cookies:
                    if cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'):
                         print("Cookie is httpOnly")
                         break
                    else:
                         print("Cookie is not httpOnly")
                         break    
               
          cookiesscan(domain)               

          
          
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




          

     

                   	
          





# define host and port numbers to scan
def scan_ports():
     # wait for the user to enter a domain name
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
    
    print(f'Scanning {host}...')
    # create the thread pool
    with ThreadPoolExecutor(len(ports)) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, [host]*len(ports), ports)    
        # report results in order
        for port,is_open in zip(ports,results):
            if is_open:
               # add the port to the list
                portslist.append(port)
                
               #  loop through the list and print the ports
        for i in range(100):
               time.sleep(0.001)
               progress['value'] += 1
               win.update_idletasks()
        progress['value'] = 0
    print(f'Open ports on {host}: {portslist}')

    for port in portslist:
          if port == 21:
               port_list_id.append(9)
                                 
          if port == 22:
               port_list_id.append(10)
    
          if port == 23:
               port_list_id.append(11)
    
          if port == 25:
               port_list_id.append(12)
    
          if port == 53:
               port_list_id.append(13)
    
          if port == 69:
               port_list_id.append(14)
    
          if port == 8080 :  
               port_list_id.append(15)
    
          if port == 137:
               port_list_id.append(16)
    
          if port == 3306:
               port_list_id.append(17)
    
          if port == 3389:
               port_list_id.append(18)
    
          if port == 8443:
               port_list_id.append(19)
    
          if port == 433:
               port_list_id.append(20)
    
          if port == 80:
               port_list_id.append(21)
    
          if port == 139:
               port_list_id.append(22)
    
          if port == 445:
               port_list_id.append(23)

def disable():
        scan.configure(state=DISABLED)


def reset():
        # resets the button to normal
        scan.configure(state=NORMAL)
        # clears the list
        vul_list_id.clear()
        portslist.clear()
        # clears the label
        label.configure(text="Enter the URL to scan")
        label.configure(fg="black")
        label.configure(font=("Arial", 12))
        # clears the entry
        entry.delete(0,END)
        entry.focus()
        


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
                print (port_list_id)
                        


                        
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
frame = Frame(tab1)
frame.pack(pady=20)

# fit a logo to the win
logo = PhotoImage(file="logo.png")
logo_label = Label(frame,image=logo, width=700, height=500)
logo_label.grid(row=1, column=0,columnspan=3,pady=20)


# create a label
label = Label(frame, text="Enter a website to scan")
label.configure(font=("Arial", 12))
label.grid(row=2, column=0)

# create an entry
entry = Entry(frame, font=("Helvetica", 24))
entry.focus()
entry.grid(row=2, column=1)

scan=ttk.Button(frame, text= "Scan",width= 15,command= lambda: [scan_ports(), main()])
scan.grid(row=2, column=2, padx=10, pady=10)
resetb=ttk.Button(frame, text="Reset",width= 15, command=reset)
resetb.grid(row=3, column=2, padx=10, pady=10)


reportb=ttk.Button(frame, text="HTML Report",width= 15, command=report)
reportb.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

pdf=ttk.Button(frame, text="PDF Report",width= 15, command=downloadPdf)
pdf.grid(row=3, column=1, columnspan=2, padx=10, pady=10)



close=ttk.Button(frame, text="Close", command=win.destroy,width= 15)
close.grid(row=4, column=2, padx=10, pady=10)

progress = ttk.Progressbar(frame, orient=HORIZONTAL, length=250, mode='determinate')
progress.grid(row=4, column=0, columnspan=3, padx=10, pady=10)


win.mainloop()
conn.close()





