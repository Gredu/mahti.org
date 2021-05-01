---
title: "PostgreSQL"
author: "Greatman Lim"
muistiinpanoja: ["Ohjelmointi"]
---

Yliopistossa on käyty jo tietokannat läpi, mutta muistin virkistykseksi freeCodeCamp.org tuottama [Youtube-video](https://youtu.be/qw--VYLpxG4).

## Tietokannan ja taulukon luonti

`CREATE DATABASE foobar` luo foobar nimisen tietokannan. Tuhoamiseen käytetään `DROP` komentoa `CREATE` sijasta.

`\c foobar` yhdistää tietokantaan foobar.

`\d` näyttää kaikki taulut. Perään voi vielä laittaa tulukon nimien, jolloin nähdään taulun tiedot. Tällä ei kuitenkaan nähdä vielä taulukon sisältöä. `\d` näyttää myös sekvenssitaulut, eikä näitä ole yleensä kiinnostavaa katsoa. Sekvenssitaulut saa pois käyttämällä komentoa `\dt`.

Taulukon luomisessa annetaan taulukun sarakkeen nimi, tyyppi ja mahdollisesti ehtoja:
```sql
CREATE TABLE person (
  id BIGSERIAL NOT NULL PRIMARY KEY,
  first_name VARCHAR(50) NOT NULL,
  last_name VARCHAR(50) NOT NULL,
  gender VARCHAR(6) NOT NULL,
  date_of_birth TIMESTAMP NOT NULL,
  )
```
Tämä oikeastaan luo kaksi taulukkoa. Ylimääräisen taulukon nimeksi tulee `person_seq`, koska `BIGSERIAL` tyyppiä on käytetty. `BIGSERIAL` on kasvava arvo, eli luo uniikkeja avaimia, josta `person_seq` taulukko pitää huolta.

## Arvojen laittaminen tauluun
```sql
INSERT INTO person (
  first_name,
  last_name,
  gender,
  date_of_birth
  )
VALUES('Anne', 'Smith', 'FEMALE', DATE '1988-01-09')
```
`VALUES` parametrien on oltava sama kuin edellä esitettyjen tyyppien.

Onnistunut lisäys taulukkoon antaa viestin `INSERT 0 1`.

https://mockaroo.com on hyvä paikka luoda satunnaista tietoa.

## Yleistä

`\?` ohjeet komentojen käyttöön.

`\i` ottaa parametrikseen .sql tiedoston, jonka se ajaa. Näin on helppo alustaa koko tietokanta.

## Tiedon hakeminen

`SELECT first_name FROM person`

`first_name` mitkä sarakkeet valitaan. Jos kaikki sarakkeet halutaan mukaan, voidaan käyttää `*`.

`person` on taulukon nimi.

## Lähteet
