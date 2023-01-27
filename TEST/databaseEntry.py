import sqlite3

conn = sqlite3.connect('vulnerabilities_db.sqlite') 
c = conn.cursor()






# change id 2 info
# c.execute('''UPDATE vulnerability SET remediation = 'Sending the proper X-Frame-Options in HTTP response headers that instruct the browser to not allow framing from other domains.
# X-Frame-Options: DENY  It completely denies to be loaded in frame/iframe.
# X-Frame-Options: SAMEORIGIN It allows only if the site which wants to load has a same origin.
# X-Frame-Options: ALLOW-FROM URL It grants a specific URL to load itself in a iframe. However please pay attention to that, not all browsers support this.
# Employing defensive code in the UI to ensure that the current frame is the most top level window.'
# WHERE vuln_id = 1''')

# add a column to the table
# c.execute('''ALTER TABLE vulnerability ADD COLUMN color TEXT''')
# update multiple rows color
# c.execute('''UPDATE vulnerability SET color = 'green' WHERE vuln_id = 1''')
# c.execute('''UPDATE vulnerability SET color = 'green' WHERE vuln_id = 2''')
# c.execute('''UPDATE vulnerability SET color = 'yellow' WHERE vuln_id = 3''')
# c.execute('''UPDATE vulnerability SET color = 'green' WHERE vuln_id = 4''')
# c.execute('''UPDATE vulnerability SET color = 'red' WHERE vuln_id = 5''')
# c.execute('''UPDATE vulnerability SET color = 'yellow' WHERE vuln_id = 6''')
# c.execute('''UPDATE vulnerability SET color = 'orange' WHERE vuln_id = 7''')
c.execute('''UPDATE vulnerability SET summary = 'This port is an alternative HTTPS port and a primary protocol that the Apache Tomcat web server utilizes to open the SSL text service.
' WHERE vuln_id = 22''')
# c.execute('''UPDATE vulnerability SET color = 'green' WHERE vuln_id = 9''')
# c.execute('''UPDATE vulnerability SET color = 'yellow' WHERE vuln_id = 25''')
# c.execute('''UPDATE vulnerability SET color = 'yellow' WHERE vuln_id = 26''')


# # switch id 
# c.execute('''UPDATE vulnerability SET vuln_id = 9 WHERE vuln_id = 27''')
# c.execute('''UPDATE vulnerability SET vuln_id = 25 WHERE vuln_id = 10''')
# c.execute('''UPDATE vulnerability SET vuln_id = 7 WHERE vuln_id = 29''')

# c.execute('''UPDATE vulnerability SET vuln_id = 10 WHERE vuln_id = 29''')


# how to switch id between two rows
# c.execute('''UPDATE vulnerability SET vuln_id = 2 WHERE vuln_id = 3''')
# c.execute('''UPDATE vulnerability SET vuln_id = 3 WHERE vuln_id = 2''')
# c.execute('''UPDATE vulnerability SET vuln_id = 2 WHERE vuln_id = 3''')
# c.execute('''UPDATE vulnerability SET vuln_id = 27 WHERE vuln_id = 26''')
# c.execute('''UPDATE vulnerability SET vuln_id = 26 WHERE vuln_id = 25''')
# c.execute('''UPDATE vulnerability SET vuln_id = 25 WHERE vuln_id = 24''')
# c.execute('''UPDATE vulnerability SET vuln_id = 24 WHERE vuln_id = 23''')
# c.execute('''UPDATE vulnerability SET vuln_id = 23 WHERE vuln_id = 22''')
# c.execute('''UPDATE vulnerability SET vuln_id = 22 WHERE vuln_id = 21''')
# c.execute('''UPDATE vulnerability SET vuln_id = 21 WHERE vuln_id = 20''')
# c.execute('''UPDATE vulnerability SET vuln_id = 20 WHERE vuln_id = 19''')
# c.execute('''UPDATE vulnerability SET vuln_id = 19 WHERE vuln_id = 18''')
# c.execute('''UPDATE vulnerability SET vuln_id = 18 WHERE vuln_id = 17''')
# c.execute('''UPDATE vulnerability SET vuln_id = 17 WHERE vuln_id = 16''')
# c.execute('''UPDATE vulnerability SET vuln_id = 16 WHERE vuln_id = 15''')
# c.execute('''UPDATE vulnerability SET vuln_id = 15 WHERE vuln_id = 14''')
# c.execute('''UPDATE vulnerability SET vuln_id = 14 WHERE vuln_id = 13''')
# c.execute('''UPDATE vulnerability SET vuln_id = 13 WHERE vuln_id = 12''')
# c.execute('''UPDATE vulnerability SET vuln_id = 11 WHERE vuln_id = 28''')



# c.execute('''UPDATE vulnerability SET color = 'red' 

# WHERE vuln_id = 1''')

# add new vulnerability
# c.execute('''INSERT INTO vulnerability (vuln_id, vuln_name, severity, impact, summary, remediation) VALUES (
# 9,

# 'Referrer-Policy', 

# 'Best Practice',

# 'Referer header is a request header that indicates the site which the traffic originated from. If there is no adequate prevention in place, the  URL itself, and even sensitive information contained in the URL will be leaked to the cross-site.

# The lack of Referrer-Policy header might affect privacy of the users and site''s itself', 

# 'Referrer-Policy is a security header designed to prevent cross-domain Referer leakage. ',

# 'In a response header:<br>

# Referrer-Policy: no-referrer | same-origin | origin | strict-origin | no-origin-when-downgrading 
# In a META tag <br>

#  &lt;meta name="Referrer-Policy" value="no-referrer | same-origin"/&gt;
# In an element attribute<br>

#  &lt;a href="http://crosssite.example.com" rel="noreferrer"&gt; &lt;/a&gt; 
# or<br>

#  &lt;a href="http://crosssite.example.com" referrerpolicy="no-referrer | same-origin | origin | strict-origin | no-origin-when-downgrading"&gt; &lt;/a&gt;' )''')




# # drop multiple rows
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 2''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 3''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 4''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 5''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 6''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 7''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 8''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 9''')
# c.execute('''DELETE FROM vulnerability WHERE vuln_id = 10''')



conn.commit()