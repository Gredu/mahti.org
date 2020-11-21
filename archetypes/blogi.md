---
title: "{{ replace .Name "-" " " | humanize }}"
author: "Greatman Lim"
blogit: ["{{ .Dir | path.Base | humanize }}"]
date: "{{ now.Format "2006-01-02" }}"
---

