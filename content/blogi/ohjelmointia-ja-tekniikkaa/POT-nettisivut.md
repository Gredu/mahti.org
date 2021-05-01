---
title: "Pohjalaisten tanssikerhon nettisivut"
author: "Greatman Lim"
blogit: ["Ohjelmointia ja tekniikkaa"]
date: "2021-05-01"
---
Pohjalaisten tanssikerho on Pohjalaisten osakuntien, eli Vasa Nationin, Etelä-Pohjalaisten ja Pohjois-Pohjalaisten osakuntien yhteinen tanssikerho. Toimin tässä kerhossa puheenjohtajana vuonna 2019 ja varapuheenjohtajana vuosina 2020 ja 2021. Tämä blogi on kirjoitettu vuonna 2021, eli olen saattanut jatkaa hallituksessa.

Aloin suunnitelemaan nettisivuja jo puheenjohtajakaudella, mutta nettisivut valmistuivat vasta vuoden 2020 varapuheenjohtajakaudella. Syy viivästykseen oli puheenjohtajan työläs virka, enkä halunnut käyttää kaikkea vapaata aikaani järjestöasioihin. Projektia myös viivästytti tanssikerhon hallituksen tietyt linjaukset. Tämän artikkelin tarkoituksena ei ole kuitenkaan avata järjestötoimintaa tai Pohjalaisten tanssikerhon hallituksen työtapoja, vaan kertoa tanssikerhon nettisivujen rakentamisesta.

Nettisivut ovat elossa osoitteessa https://pohjalaiset.fi/tanssikerho ja sen versionhallinta githubissa osoitteessa https://github.com/pohjalaisten-tanssikerho/web-page

Versionhallinnan etusivulle on kirjoitettu ohjeita koodaajille, jos joku haluaa auttaa nettisivujen rakentamisessa. Etusivu kannattaa lukea myös, jos on kiinnostunut nettisivuista ihan kooditasolla.

Nettisivujen tärkeimmät rakennuspalikat:

  - [Hugo](https://gohugo.io) staattisten sivujen generointiin
  - [sass](https://sass-lang.com/) css esiprosessointiin
  - [CircleCI](https://circleci.com) nettisivujen automaattiseen päivitykseen ja käyttöönottoon
  - [Forestry](https://forestry.io) CMS (Content Management System)

Näiden lisäksi luonnollisesti javascript ja html.

## Hugo

Hugo on ollut tämän projektin tärkein työkalu. Se on staattisten sivujen generoija, joka luo html-, css- ja javascript tiedostot, jotka voi heittää esimerkiksi dummy palvelimiin. Dummyllä tarkoitan yksikertaista palvelinta, joka osaa näyttää html ja css tiedostoja. Palvelimelta ei esimerkiksi vaadita tietokantaa tai php-tulkkausta.

Vaikka Hugon luomat html ja css tiedostot ovatkin staattisia ja yksinkertaisia, voi Hugolle kirjoitettu koodi olla monimutkainen. Hugo siis lukee sille kirjoitettua koodia ja generoi näistä staattiset sivut.

Hugon käyttö vaatii nettisivuperusteiden hallintaa (html ja css) ja hieman yleistä ohjelmointitaitoa. Hugon syntaksi on [go:n](https://golang.org/) kaltainen, sillä onhan Hugo tehty go kieltä käyttäen.

Hyvä paikka aloittaa Hugo on katsoa [Mike Danen Youtube videosarja](https://www.youtube.com/watch?v=qtIqKaDlqXo&list=PLLAZ4kZ9dFpOnyRlyS-liKL5ReHDcj4G3) ja vasta tämän jälkeen käydä läpi Hugon dokumentaatio. Alulle pääseminen on vaikeaa, koska kokonaiskuvan hahmottaminen on hankalaa. Tutkiskelun jälkeen Hugo toimii kuitenkin erittäin loogisesti ja sitä on helppo käyttää.

## CircleCI ja Forestry

Pohjalaisten tanssikerhon nettisivujen etusivulla näytetään aina kolme seuraavaa tapahtumaa. Näihin ei ole käytetty javascriptiä, vaan Hugo generoi joka päivä uudet staattiset sivut. CircleCI tekee tämän joka yö noin kahden aikaan ja lähettää generoidut tiedostot Pohjalaisten palvelimeen.

Tämä ratkaisu saattaa tuntua aika raskaalta, mutta on oikeastaan yllättävän kevyt. Ehkä kuitenkin parempi menetelmä olisi ollut käyttää javascriptiä, mutta silloisessa tilanteessa kiinnostus oli oppia enemmän Hugoa ja CircleCI:tä.

Vaikka javascriptistä olisikin otettu käyttöön, ei CircleCI:stä kuitenkaan olisi päästy eroon. Jotta muukin kuin tekninen asiantuntija pystyisi nettisivuja päivittämään, on pakko automatisoida ns. *build and deploy* sykli. Tämä tapahtuu käytännössä siten, että kun versionhallintaan tulee muutos, CircleCI havaitsee sen ja käynnistää syklin.

Versionhallinnan, eli Githubin ja gitin käyttö on hankala koodaustaidottomalle. Nettisivun sisältöä voi kuitenkin ainoastaan versionhallinnasta päivittää tai muokata. Tässä kohtaa Forestry tulee mukaan. Sen ansiosta versionhallinta onnistuu jokaiselta.

Sisällön tuottajan ei tarvitse ymmärtää taustalla tapahtuvista asioista. Käytännössä se mitä tapahtuu on, että kun muutokset on tehty versionhallintaan Forestryllä, CircleCI nappaa koodin ja suorittaa *Build and deploy* syklin. Sivut siis rakennetaan uudelleen ja lähetetään palvelimeen, johon osoite pohjalaiset.fi/tanssikerho vie.

Sisällön tuottaja ei välttämättä edes tunne käsitettä versionhallinta, Github tai git, mutta ei hänen tarvitsekaan. Forestry näyttää ihan tavalliselta CMS:ltä, eikä miltään versionhallintasovellukselta, vaikka se sitä sisimmältään oikeasti on.

## Entäs Netlify?

Alunperin nettisivut julkaistiin [Netlifyn](https://www.netlify.com/) alustassa, koska Netlifystä minulla on ollut eniten kokemusta. Netlify tekee vähän samaa, kuin mitä CircleCI, mutta on enemmän räätälöity Hugon kaltaisille staattisten sivujen generoijille. NetlifyCMS integroituu hyvin Netlify palveluun ja olisi voinut korvata Forestryn. Tämä paketti ei kuitenkaan voinut Pohjalaisten tanssikerhon tapauksessa ottaa käyttöön, sillä tanssikerhon nettisivut julkaistaan alihakemistossa (https://pohjalaiset.fi/tanssikerho). Käytännössä minulla pitäisi olla oikeus domainiin juureen (pohjalaiset.fi), jotta voisin automatisoida *build and deploy* prosessin.

CircleCI ja Forestry kombo on monimutkaisempi kuin Netlify ja NetlifyCMS, mutta CircleCI pystyy lähes kaikkeen. Tarve oli julkaista nettisivut alihakemistoon, mihin Netlify ei pystynyt.

Alussa nettisivuja oli kaksi versiota: Netlifyssä ja Pohjalaisten tanssikerhon palvelimessa. Pohjalaisten Valtuuskunnalle oli käynyt se, että he laittaisivat pohjalaiset.fi/tanssikerho osoittamaan Netlifyn palvelimeen. Mitään ei kuitenkaan tapahtunut vuoteen - eikä vieläkään ole asialle tehty mitään neljännenkään sähköpostimuistutuksen jälkeen - ja kahden samanlaisen nettisivun ylläpitäminen alkoi jo käydä raskaaksi. Piti keksiä joku järkevämpi tapa ja CircleCI ja Forestry olivat ratkaisu.

*Build and deploy* ei ole mitenkään monimutkainen operaatio. Tästä oikeastaan teinkin scriptin, mutta olisi ollut turha olettaa, että sisällön tuottaja olisi tätä osannut käyttää. Lisäksi suurin osa ihmisistä käyttää Microsoft Windowssia, mutta scripti käynnistetään POSIX-yhteensopivalla shellillä. Unixissa taas devaus-ympäristön pitäisi olla kunnossa.

## Domain ja SSL

Osoitteella pohjalaiset.fi/tanssikerho oli muitakin ongelmia kuin saada osoitteen uudelleen reitittäminen.

Alihakemistossa oleva nettisivu on semanttisesti huono idea. Yleensä alihakemistossa on nettisivun resurssi tai vähintäänkin saman organisaation näköinen sivusto. Alihakemistossa oleva sivu ei myöskään kovin helposti toimi yhteen Netlifyn, Forestryn tai jonkun muun palveluntarjoajan kanssa. Esimerkiksi en ole onnistunut saamaan esikatselua toimimaan (Netlify, NetlifyCMS ja Forestry). Tällä hetkellä ongelmana on, että sisällön tuottajat joutuvat kirjoittamaan tekstiä näkemättä, miltä lopputulos näyttää nettisivuilla. Monelle palveluntarjoajalle on yksinkertaisesti vain outoa pitää kokonaista nettisivua alihakemistossa.

Pohjalaisten nettisivuilla ei ole ollut [SSL-suojausta](https://www.websecurity.digicert.com/security-topics/what-is-ssl-tls-https), mikä vaikuttaa myös tanssikerhon nettisivuihin. SSL-suojausta ei tietääkseni ole mahdollista hankkia alihakemistossa olevalle nettisivulle, vaan SSL-suojaukset vaikuttavat koko domainiin (alidomain on kuitenkin eri asia). Pohjalaisten Valtuuskunnan nettisivut eivät näytä keräävään arkaluonteista tietoa. Nopeasti vilkaistuna nettisivujen kautta voi lähettää ainoastaan juhlailmoituksia. Sen sijaan Pohjalaisten tanssikerhon nettisivujen kautta ilmoittaudutaan tanssikursseille. Koska tanssikerho on yhdistys, on sen ylläpidettävä jäsenrekisteriä. Käytännössä tanssijoilta kerätään asumistietoja (paikkakunta), sähköpostiosoite, nimet jne. jotta se täyttää jäsenreskiterin minimivaatimukset. Pohjalaisten nettisivut eivät siis tarvitsisi SSL-suojasta, mutta Pohjalaisten tanssikerhon nettisivuille se voisi olla hyvä.

Mielestäni SSL kannattaa hankkia muutenkin, vaikka nettisivut eivät käsittelisikään arkaluonteista tietoa, koska hakukoneet suosivat suojattuja sivuja. Lisäksi SSL-suojauksen hankkiminen on helppoa ja nykyään ilmaista. Vihjasin Pohjalaisten Valtuuskunnalle, että nettisivun suojaaminen voisi olla hyvä juttu ja vuoden päästä he saivatkin sen tehtyä (2021 alussa). En ole kuitenkaan varma johtuiko se antamastani vihjeestä.

Olen kertonut Pohjalaisten Valtuuskunnalle, miten hankala alihakemistossa olevat nettisivut ovat. Tämän voi korjata helposti luomalla tanssikerholle alidomainin, jolloin osoite olisi muotoa tanssikerho.pohjalaiset.fi . Tämä olisi hyvä semanttimen parannus ja hakukoneetkin pitäisivät siitä. CMS:ään saataisiin toimimaan myös esikatselu, jos domainin muutoksen toteutus tehdään oikein.

Oikeastaan en ole ihan varma siitä, miten alidomain toteutetaan tai miten se kannattaa toteuttaa. Asian voisi hoitaa `redirect 301` ohjauksella osoitteesta pohjalaiset.fi/tanssikerho osoitteeseen tanssikerho.pohjalaiset.fi ja kohdeosoitteessa olisi uusi palvelin, jossa nettisivut ovat. Tämä olisi tämän hetkisellä ratkaisuilla (CircleCI ja Forestry) varmaan paras.

Kun Pohjalaisten tanssikerhon nettisivut olivat Netlify alustalla, silloin helpoin ja paras tapa olisi ollut vain uudelleen ohjata osoitteista pohjalaiset.fi/tanssikerho ja tanssikerho.pohjalaiset.fi osoittamaan Netlifyn alustaan.

## Kokemuksia sivujen rakentamisesta

Pohjalaisten tanssikerhon nettisivujen rakentaminen oli helppoa. Tämä ei ollut ensimmäinen kerta, kun rakennan nettisivuja Hugolla. Tätä ennen on ollut jo aika vahva osaaminen nettisivujen peruspalikoista, kuten HMTL, CSS ja javascript.

Isoimmat vaikeudet olivat oikeastaan sisällön tuotannossa, johon meni aikaa kaikista eniten. Sinänsä ehkä huono asia, sillä Pohjalaisten tanssikerhon hallituksen muut jäsenet olisivat voineet tehdä sen. Olin kuitenkin ainoa joka osasi tehdä nettisivuja. Lisäksi, koska en ole ihan täysin suomalainen, ei minun suomen kielen kirjoittaminen välttämättä ollut hallituksen parhaimpia.

Nettisivun taksonomia ja sisällön tuottamisessa auttoivat Pohjalaisten tanssikerhon vanhat nettisivut. Näissä oli jo vähän sisältöä, joka auttoi hahmottamaan, mitä kaikkea netisivuilla pitäisi olla. Näin on helpompi suunnitella nettisivut oikean kokoisiksi. Muissa projekteissa on ollut välillä ongelmia siinä, että asiakas on ilmoittanut sisällön olevan määrältään suuri, vaikka sitä oli tullut loppujen lopuksi aika vähän. Lopputuloksena nettisivut suunniteltiin liian suureksi. Tekstin ympärillä on ollut liikaa tilaa ja kokonaisilme on kärsinyt.

Grafiikan teko oli yllättävän helppoa. Olin ollut siinä luulossa, että siihen olisi voinut mennä kauemminkin. Onneksi **Tomi Päiväniemi** oli antanut kuvia käyttöön ja kuvissa esiintyneet tanssijat olivat myös antaneet suostumuksensa. Kuvat ja grafiikka yhdessä on tehnyt nettisivuista yllättävän kauniit! Värimaisema on rohkea ja muista hyvin erottuva. Sävyn inspiraatiotana on ollut tumman yönsininen taivas ja valkoisina hohtavat tähdet, sekä pieni aamunkajon lupaus, mikä näkyy oranssina ja lämpönä. Tätähän ei sivulla vierailevat välttämättä näe, mutta uskoisin ainakin tunnelman välittyvän.
