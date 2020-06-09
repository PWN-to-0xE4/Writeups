## Getting admin

### Writeup by dvoak, 300 points

`See if you can get an admin account.`

Looking at cookies, a new Javascript Web Token has appeared.
Decoding this, we get:

-	{"user": null, "privilege": null}

Becomes clear this is influnced by our UNION injection.
Changing values, it's reflected that the order follows username, password, privilege.

The /admin page stops having errors when priviledge is a number, which indicates thats what its checking for.


From trying numbers, privilege == 2 reveals the flag -

Therefore: ' UNION SELECT NULL,NULL,2 -- -

## Flag: ractf{j4va5cr1pt_w3b_t0ken}


