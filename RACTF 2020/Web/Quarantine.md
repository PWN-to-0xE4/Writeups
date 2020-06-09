# Quarantine

### Writeup by dvoak, 200 points

`See if you can get access to an account on the webapp.`

Need to enumerate the login page in order to determine columns in the DB as it's a blind injection.

UNION Injection allows achieving this.

' UNION SELECT NULL,NULL,NULL -- -

## Flag: ractf{Y0u_B3tt3r_N0t_h4v3_us3d_sqlm4p}  
