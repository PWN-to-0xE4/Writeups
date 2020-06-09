# Admin Attack

### Writeup by dvoak, 300 points

`Looks like we managed to get a list of users. That admin user looks particularly interesting, but we don't have their password. Try and attack the login form and see if you can get anything.`

This time around we repeat the same process and get an invalid login.

Repeating the ' break in the username we see: 
-	cur.execute("SELECT algo FROM users WHERE username='{}'".format(

There appears to be some sort of selection in place to check if the password is hashed - if so then the password is hashed before being passed. 

Therefore, we must inject from username field. We effectively bypass this by filling out the entire query, making it result as true, using this payload:

jimmyTehAdmin' OR username == 'jimmyTehAdmin' AND True -- -


## Flag: ractf{!!!4dm1n4buse!!!}
