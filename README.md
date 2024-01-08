# MTAN-Tracker

A simple tools for collecting packet capture files (as well as malware samples) from [MALWARE-TRAFFIC-ANALYSIS.NET](https://www.malware-traffic-analysis.net/index.html)

![](https://www.malware-traffic-analysis.net/site-logo-01.gif)

## Announcement
All blog posts were moved by the author(@brad), so the main code no longer access the materials from the [official website](https://www.malware-traffic-analysis.net/). ~~My work, and my efforts are totally gone!~~ (✖~ ∧ ✖~ 

However, anything originally posted is now contained in password-protected zip archives by year in the [archived section](https://www.malware-traffic-analysis.net/archived/index.html).

## Usage
Install below two libraries.
```
$ go get github.com/PuerkitoBio/goquery
$ go get github.com/yeka/zip
```

And then, just `go`
```
$ go run main.go
```