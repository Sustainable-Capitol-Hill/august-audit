# August Audit

This script parses and analzyes an August smart lock access log CSV file, looking for cases where doors have been accidentally left unlocked or open for unusually long periods of time.

An August admin user can [download the log file](https://account.august.com), and then run this script on it.

## Example

> [!NOTE]  
> The logs below have been tweaked for anonymization and secruity

Command:

```shell
./august-analyzer.py august_data_2026-03-15T21-30-18+00-00/activity.csv
```

Output:

```
Analyzing the August access log that covers the past 29 days…

Cases when a door was open for more than 6 hours:

- Starting on Mon Mar 2 at 1:43 PM PST, the Front Door remained open for 6 hours.
- Starting on Fri Mar 6 at 5:32 PM PST, the Back Door remained open for 6 hours.

Cases when a door was unlocked for more than 6 hours:

- Starting on Sun Feb 15 at 2:49 PM PST, the Inventory Room remained unlocked for 24 hours. It was originally unlocked by Ali Young.
- Starting on Thu Feb 19 at 5:55 PM PST, the Front Door remained unlocked for 6 hours. It was originally unlocked by Daniel Conrad.
- Starting on Sun Feb 22 at 12:09 PM PST, the Back Door remained unlocked for 7 hours. It was originally unlocked by an unidentified user.
- Starting on Sun Mar 8 at 12:05 AM PST, the Bathroom remained unlocked for 11 hours. It was originally unlocked by an unidentified user.
- Starting on Thu Mar 12 at 7:53 PM PDT, the Bathroom remained unlocked for 6 hours. It was originally unlocked by an unidentified user.
```
