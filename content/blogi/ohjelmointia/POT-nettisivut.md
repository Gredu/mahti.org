---
title: "Pohjalaisten tanssikerhon nettisivut"
author: "Greatman Lim"
blogit: ["Ohjelmointia"]
date: "2021-03-21"
draft: true
---
Pohjalaisten tanssikerho on Pohjalaisten osakuntien, eli Vasa Nation, Etelä-Pohjalaisten ja Pohjois-Pohjalaisten osakuntien yhteinen tanssikerho. Toimin tässä kerhossa puheenjohtajana vuotena 2019 ja varapuheenjohtajana vuosina 2020 ja 2021. Tämä blogi on kirjoitettu vuonna 2021, eli olen saattanut jatkaa hallituksessa.

Aloin suunnitelemaan nettisivuja jo puheenjohtajakaudella, mutta itse nettisivut valmistuivat vasta 2020 varapuheenjohtajakaudella. Syy viivästykseen olivat puheenjohtajan työläs virka, enkä halunnut käyttää kaikkea vapaata aikaani järjestöasioissa. Projektia myös viivästytti tanssikerhon hallituksen tietyt linjaukset. Tämän artikkelin tarkoituksena ei ole kuitenkaan avata järjestötoimintaa tai Pohjalaisten tanssikerhon hallituksen työtapoja, vaan kertoa tanssikerhon nettisivujen rakentamisesta.

Nettisivut ovat elossa osoitteessa https://pohjalaiset.fi/tanssikerho

Nettisivujen rakennuspalikat:

  - [Hugo](https://gohugo.io) staattisten sivujen generointiin
  - [sass](https://sass-lang.com/) css esiprosessointiin
  - [CircleCI](https://circleci.com) nettisivujen automaattiseen päivitykseen ja käyttöönottoon

Näiden lisäksi luonnollisesti javascript ja html.

## Hugo

Hugo on ollut tämän projektin tärkein työkalu. Se on staattisten sivujen generoija, joka luo html-, css- ja javascript tiedostot, jotka voi heittää esimerkiksi dummy palvelimiin. Dummyllä tarkoitan yksikertaista palvelinta, joka osaa näyttää html ja css tiedostoja. Palvelimelta ei esimerkiksi vaadita tietokantaa tai php-tulkkausta.

Vaikka Hugon luomat html ja css tiedostot ovatkin staattisia ja yksinkertaisia, voi Hugolla kirjoitettu koodi olla monimutkainen. Eli yksinkertaistettuna kirjoitetaan Hugon ymmärtävää koodia, josta Hugo generoi staattiset sivut.
