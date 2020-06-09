# Entrypoint

### Writeup by dvoak, 200 points

`Sadly it looks like there wasn't much to see in the python source. We suspect we may be able to login to the site using backup credentials, but we're not sure where they might be. Encase the password you find in ractf{...} to get the flag. `

`**This challenge does NOT have fake flags.** If you found some other flags while solving this challenge, you may have found the solutions to the next challenges first :P`

View source, refer to /backup.txt.

We receive a 403 Forbidden error.

Back to source, reference to static?f=index.css

Replace this with backup.txt.

## Flag: ractf{developerBackupCode4321}
