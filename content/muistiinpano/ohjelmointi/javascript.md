---
title: "javascript"
author: "Greatman Lim"
muistiinpanoja: ["Ohjelmointi"]
---

Henkilökohtaisia muistiinpanoja javascriptistä, mikä ei ole tarkoitettu oppimateriaaliksi. Sisältö koostuu pääosin suunnittelumalleista ja funktionaalisesta ohjelmoinnista.

## var, let vai ei mitään? [^1]

Lähes aina kannattaa käyttää joko `let` tai `const` muuttujia nimittäessä.

`var` näkyvyysalue vuotaa `for` lauseessa, joka on hieman outo ominaisuus, jos on ohjelmoinut muilla kielillä. `var` näkyvyys pysyy kuitenkin funktion sisällä. Jos muuttuja luodaan ilman avainsanaa, tulkkaaja pyrkii etsimään saman nimisen muuttujan ylemmästä hierarkiasta. Jos muuttujaa ei löydy, javascript luo sen ylimpään hierarkiaan, eli muuttujasta tulee globaali. Yleensä tämä ei ole haluttu ominaisuus, ja se voidaan estää kirjoittamalla javascript tiedoston ensimmäiseksi riviksi `"use strict";`.

## Milloin puolipilkku on tarpeellinen?

Jos seuraava rivi alkaa sululla `(`, on ylempään riviin laitettava puolipiste. Muuten javascript luulee, että nämä kaksi ovat samaa riviä.

## Debuggaus [^4]

`console.log()` voi ottaa parametrikseen olion tai listan. Selaimet myös tukevat tyylejä.

{{< highlight javascript >}}

const foo = { name: 'tom', age: 30, nervous: false };
const bar = { name: 'dick', age: 40, nervous: false };
const baz = { name: 'harry', age: 50, nervous: true };

console.log('%c My Friends', 'color: orange; font-weight: bold;')
console.log({ foo, bar, baz })
console.log([ foo, bar, baz ])  // onnistuu vain jos olioilla on samat kentät

{{< /highlight >}}

## Suorituskykyarviointi

{{< highlight javascript >}}

console.time('foo')

let i = 0
while (i < 100000) { i++ }

console.timeEnd('foo')

{{< /highlight >}}

## Funktion jäljittäminen

{{< highlight javascript >}}

const deleteMe = () => console.trace('bye bye database') 
deleteMe()
deleteMe()

{{< /highlight >}}

## Destruktuointi

{{< highlight javascript >}}

const turtle = {
  name: 'Bob',
  legs: 4,
  shell: true,
  type: 'amphibious',
  meal: 10,
  diet: 'berries'
}

{{< /highlight >}}

Huono tapa:

{{< highlight javascript >}}

function feed(animal) {
  return `Feed ${animal.name} ${animal.meal} kilos of ${animal.diet}.`
}

{{< /highlight >}}

Hyvä tapa:

{{< highlight javascript >}}

function feed({ name, meal, diet }) {
  return `Feed ${name} ${meal} kilos of ${diet}.`
}

{{< /highlight >}}

Toinen hyvä tapa:

{{< highlight javascript >}}

function feed(animal) {
  const { name, meal, diet } = animal
  return `Feed ${name} ${meal} kilos of ${diet}.`
}

{{< /highlight >}}

## Nuolifunktiot [^2]

Nuolifunktio ei ole pelkästään lyhennös avainsanalle `function`. Nuolifunktioissa `this` ei toimi samalla tavalla kuin perinteisessä funktiossa.

Oletetaan, että on seuraavanlainen taulukko, jossa on objekteja:

{{< highlight javascript >}}

const dragonEvents = [
  { type: 'attack', value: 12, target: 'player-dorkman' },
  { type: 'yawn', value: 40 },
  { type: 'eat', target: 'horse' },
  { type: 'attack', value: 23, target: 'player-fluffykins' },
  { type: 'attack', value: 12, target: 'player-dorkman' }
]

{{< /highlight >}}

Seuraavaksi on laskettava player-dorkmannin yhteinen hyökkäys summa. Tehdään seuraavalla tavalla:

  1. suodatetaan `attack`
  2. suodatetaan `player-dorkman`
  3. kerätään `value` kenttien arvot
  4. lasketaan kerätyt arvot yhteen

Käytetään normaaleja funktioita:

{{< highlight javascript >}}

const totalDamageOnDorkman = dragonEvents
  .filter(function(event) {
  return event.type === 'attack'
  })
  .filter(function(event) {
    return event.target === 'player-dorkman'
  })
  .map(function(event) {
    return event.value
  })
  .reduce(function(prev, value) {
    return (prev || 0) + value
  })

{{< /highlight >}}

Edellinen koodi refraktuoitu nuolifunktioita käyttäen:

{{< highlight javascript >}}

const totalDamageOnDorkman = dragonEvents
  .filter((event) => {
  return event.type === 'attack'
  })
  .filter((event) => {
    return event.target === 'player-dorkman'
  })
  .map((event) => {
    return event.value
  })
  .reduce((prev, value) => {
    return (prev || 0) + value
  })

{{< /highlight >}}

Mutta voidaan saada vielä paremmaksi:

{{< highlight javascript >}}

const totalDamageOnDorkman = dragonEvents
  .filter(event => event.type === 'attack')
  .filter(event => event.target === 'player-dorkman')
  .map(event => event.value)
  .reduce((prev, value) => (prev || 0) + value)

{{< /highlight >}}

Jos funktiolla vain yksi rivi koodia, voidaan poistaa aaltosulut ja `return`. Myöskin parametrien ympäriltä voidaan ottaa sulut pois, paitsi silloin kun parametrejä on kaksi tai enemmän.

## Funktionaalinen ohjelmointi [^3]

Funktio normaalisti:

{{< highlight javascript >}}

function triple(x) {
  return x * 3
}

{{< /highlight >}}

Funktionaalisessa ohjelmoinnissa funktiot ovat arvoja muuttujissa.

{{< highlight javascript >}}

let triple = function(x) {
  return x * 3
}

let foo = triple
foo(30)

{{< /highlight >}}

Koska funktio on arvo muuttujassa, voidaan kyseinen muuttuja antaa argumenttina toiselle funktiolle.

Oletetaan, että on taulukko, jossa on objekteja:

{{< highlight javascript >}}

let animals = [
  { name: 'Fluffyskins', species: 'rabbit' },
  { name: 'Caro', species: 'dog' },
  { name: 'Hamilton', species: 'dog' },
  { name: 'Harold', species: 'fish' },
  { name: 'Ursula', species: 'cat' },
  { name: 'Jimmy', species: 'fish' }
]

{{< /highlight >}}

Kerätään kaikki koirat samalla taulukolle käyttäen toistorakennetta `for`.

{{< highlight javascript >}}

let dogs = []
for (let i = 0; i < animals.length; i++) {
  if (animals[i].species === 'dog')
    dog.push(animals[i])
}

{{< /highlight >}}

Sama kuin edellinen `filter` funktiolla:

{{< highlight javascript >}}

let dogs = animals.filter(animal => animal.species === 'dog' )

{{< /highlight >}}

Uudelleenkäyttettävyys esimerkki: käytetään funktiota `.reject`:

{{< highlight javascript >}}

let isDog = (animal => animal.species === 'dog' )
let dogs = animals.filter(isDog)
let otherAnimals = animals.reject(isDog)

{{< /highlight >}}

### map

Käytetään samaa eläintaulukkoa kuin edellisessä kappaleessa. Nyt tavoitteena on kerätä kaikki eläinten nimet yhdeksi taulukoksi. Ratkaistaan se toistorakenteella:

{{< highlight javascript >}}

let names = []
for ( var i = 0; i < animals.length; i++ ) {
  names.push(animals[i].name)
}

{{< /highlight >}}

Sama `map` funktiolla:

{{< highlight javascript >}}

let names = animals.map(animal => animal.name)

{{< /highlight >}}

Voidaan lisätä:

{{< highlight javascript >}}

let names = animals.map(animal => animal.name + ' is a ' + animal.species)

{{< /highlight >}}

### reduce

Funktio `reduce` on hyvä, kun mikään muu ei toimi. Käytännössä `reduce` voi korvata kaikki muut, eli se on yleispätevä työkalu. Käytetään seuraavanlaista tietokantaa:

{{< highlight javascript >}}

let orders = [
  { amount: 250 },
  { amount: 400 },
  { amount: 100 },
  { amount: 325 }
]

{{< /highlight >}}

Lasketaan kaikki yhteen toistorakenteella:

{{< highlight javascript >}}

let totalAmount = 0
for (let i = 0; i < orders.length; i++) {
  totalAmount += orders[i].amount
}

{{< /highlight >}}

Funktion `reduce` kanssa:

{{< highlight javascript >}}

let totalAmount = orders.reduce((sum, item) => sum + item.amount, 0)

{{< /highlight >}}

Huomaa, että funktio `reduce` ottaa parametrin. Tämä on esimerkissä argumenttille `sum` tarkoitettu arvo.

Katsotaan seuraavaksi hieman vaikeampaa esimerkkiä.Oletetaan, että on tekstitiedosto `data.txt`, missä eri kentät on rajattu tabulaattoria käyttäen:

{{< highlight text >}}

mark johansson waffle iron 80 2
mark johansson blende 200 1
mark johansson knife 10 4
Nikita Smith waffle iron 80 1
Nikita Smith knife 10 2
Nikita Smith pot 20 3

{{< /highlight >}}

Tehtävänä on muuttaa edellinen tekstitiedosto muotoon:

{{< highlight javascript >}}

{
  'mark johansson': [
    { name: 'waffle iron', price: '80', quantity: '2' },
    { name: 'blender', price: '200', quantity: '1' },
    { name: 'knife', price: '10', quantity: '4' },
  ]
  'Nikita Smith': [
    { name: 'waffle iron', price: '80', quantity: '1' },
    { name: 'knife', price: '10', quantity: '2' },
    { name: 'pot', price: '20', quantity: '3' },
  ]
}

{{< /highlight >}}

Vastaus:

{{< highlight javascript >}}

import fs from 'fs'

let output = fs.readFileSync('data.txt', 'utf8')
  .trim() // poistetaan lopusta ylimääräinen merkki
  .split('\n')
  .map(line => line.split('\t'))
  .reduce((customers, line) => {
    customers[line[0]] = customers[line[0]] ||  []
    customers[line[0]].push({
      name: line[1],
      price: line[2]
      quantity: line[3]
    })
  }, {})

console.log('output', JSON.stringify(output, null, 2))

{{< /highlight >}}

### Sulkeumat

Funktioilla on pääsy funktion ulkopuolella määriteltyihin muuttujiin.

{{< highlight javascript >}}

let me = "Bruce Wayne"

function greetMe() {
  console.log("Hello, " + me + "!")
}

{{< /highlight >}}

Kun funktio käynnistetään...

{{< highlight javascript >}}

greetMe()

{{< /highlight >}}

... tulostaa ohjelma `Bruce Wayne`, koska funktio pääsee käsiksi muuttujaan `me`. Arvo luetaan aidosti muuttujasta sillä seuraava ohjelma tulostaa `Batman`:

{{< highlight javascript >}}

me = "Batman"
greetMe()

{{< /highlight >}}

Jos kieli ei tue sulkeumia, olisi muuttuja annettava argumenttina funktioille tai metodeille.

### Curry-muunnos

Muunnetaan funktio yksi parametrisiksi. Funktio palauttaa toisen funktion, jolla on nämä "toiset" parametrit. Käytännössä kaikki funktiot voivat palauttaa funktion, joilla on myös vain yksi parametri. Esimerkiksi jos funktiolla on kolme parametriä, Curry muunnokselta siitä saadaan kolmen funktion ketju. Näillä funktioilla on jokaisella vain yksi parametri. Funktio toimii kuitenkin samalla tavalla kuin funktio silloin, kun sillä oli kolme parametriä.

{{< highlight javascript >}}

let dragon = (name, size, element) => 
  name + 'is a ' +
  size + ' dragon that breathes ' +
  element + '!'

{{< /highlight >}}

Curry-muunnos:

{{< highlight javascript >}}

let dragon =
  name =>
    size =>
      element =>
        name + 'is a ' +
        size + ' dragon that breathes ' +
        element + '!'

{{< /highlight >}}

Tätä funktiota kutsutaan hieman eritavalla:

{{< highlight javascript >}}

console.log(dragon('fluffykins')('tiny')('lightning'))

{{< /highlight >}}

Saadaan funktiot pilkottua:

{{< highlight javascript >}}

let fluffykinsDragon = dragon ('fluffykins')
let tinyDrdagon = fluffykinsDragon('tiny')
console.log(tinyDragon('lightning'))

{{< /highlight >}}

Esimerkki Curryttamisen hyödyllisyydestä:

{{< highlight javascript >}}

let dragons = [
  { name: 'fluffykins', element: 'lightning' },
  { name: 'noomi', element: 'lightning' },
  { name: 'karo', element: 'fire' },
  { name: 'doomer', element: 'timewarp' }
]

let hasElement =
  (element, obj) => obj.element === element

let lightningDragons =
  dragons.filter(x => hasElement('lightning', x))

{{< /highlight >}}

Tuodaan projektiin `lodash`, joka Curryttaa. Tämän jälkeen sama ohjelma voidaan kirjoittaa muodossa:

{{< highlight javascript >}}

import _ from 'lodash'

let dragons = [
  { name: 'fluffykins', element: 'lightning' },
  { name: 'noomi', element: 'lightning' },
  { name: 'karo', element: 'fire' },
  { name: 'doomer', element: 'timewarp' }
]

let hasElement =
  _.curry((element, obj) => obj.element === element)

let lightningDragons =
  dragons.filter(hasElement('lightning'))

{{< /highlight >}}

### Rekursio

Funktio joka laskee kymmenestä alaspäin:

{{< highlight javascript >}}

countDown(10)

{{< /highlight >}}

Funktion toteutus rekursiolla:

{{< highlight javascript >}}

let countDownFrom = num => {
  if (num === 0) return
  console.log(num)
  countDownFrom(num - 1)
}

{{< /highlight >}}

Kaikki minkä rekursio pystyy tekemään, pystytään sama tehdä toistolauseilla, mutta ei kuitenkaan toisinpäin. Rekursio on hyvä työkalu, joka toimii joihinkin ongelmiin paremmin kuin toistolause. Edellinen tehtävä olisi esimerkiksi voitu ratkaista toistolauseella helpommin. Rekursiolla ratkaisu toimii paremmin esimerkiksi seuraavaan ongelmaan.

On seuraavanlainen taulukko, joka sisältää objekteja:

{{< highlight javascript >}}

let categories = [
  { id: 'animals', 'parent': null },
  { id: 'mammals', 'parent': 'animals' },
  { id: 'cats', 'parent': 'mammals' },
  { id: 'dogs', 'parent': 'mammals' },
  { id: 'chihuahua', 'parent': 'dogs' },
  { id: 'labrador', 'parent': 'dogs' },
  { id: 'persian', 'parent': 'cats' },
  { id: 'siamese', 'parent': 'cats' }
]

{{< /highlight >}}

Yritetään rekursiota käyttämällä ellinen taulukko seuraavanlainen muoto:

{{< highlight javascript >}}

{
  animals: {
    mammals: {
      dogs: {
        chihuahua: null
        labrador: null
      },
      cats: {
        persian: null
        siamese: null
      }
    }
  }
}

{{< /highlight >}}

Vastaus:

{{< highlight javascript >}}

let makeTree = (categories, parent) = {
  let node = {}
  categories
    .filter(c = > c.parent == parent)
    .forEach(c => node[c.id] = makeTree(categories, c.id))
  return node

console.log(
  JSON.stringify(
    makeTree(categories, null)
    , null, 2)
)

{{< /highlight >}}

### Lupaukset

Lupaukset toimivat kuten `callback` funktiot, mutta ovat hieman voimakkaampia.

{{< highlight javascript >}}

import loadImagePromised from './load-image-promised'

loadImagePromised('images/cat1.jpg')
  .then((img) => {
    let imgElement = document.createElement('img')
    imgElement.src = img.src
    document.body.appendChild(imgElement)
  })

{{< /highlight >}}

Lupaksilla on `.then` metodi. Tämän funktion algoritmi käynnistyy, kun edellinen funktio on valmis, eli tässä tapauksessa `loadImagePromised`.

Samaa tekevä funktio, jossa on `callback`:

{{< highlight javascript >}}

loadImagePromised('images/cat1.jpg', (error, img) =>
    let imgElement = document.createElement('img')
    imgElement.src = img.src
    document.body.appendChild(imgElement)
  })

{{< /highlight >}}

Alkuun näyttä siltä, että `callback` funktio on kompaktimpi kuin lupaukset. Tilanne kuitenkin monimutkaistuu, jos on monta `callback` funktiota. Seuraavassa monta `callback` funktiota. Joskus kutsutaan myös `callback` helvetiksi.

{{< highlight javascript >}}

let addImg = (src) => {
  let img = document.createElement("img")
  imgElement.src = src
  document.body.appendChild(imgElement)
}

loadImageCallbacked('imges/cat1.jpg', (error, img1) => {
  addImg(img1.src)
  loadImageCallbacked('images/cat2.jpg', (error, img2) => {
    addImg(img2.src)
    loadImageCallbacked('imges/cat3.jpg', (error, img3) => {
      addImg(img3.src)
    })
  })
})

{{< /highlight >}}

Edellinen ohjelma ei suorita funktioita samanaikaisesti, vaikka siihen voisi. Edellisessä ohjelmassa ei ole otettu huomioon virhe-ilmoitukset. Todellisessa tilanteesta `callback` funktiot saattavat isokokoisia ja vaikea pitää järkevänä.

`callback` näyttää tältä:

{{< highlight javascript >}}

function loadImage(url, callback) {
  let image = new Image()
  image.onload = function() {
    callback(null, image)
  }
  image.onerror = function () {
    let message = 'Could not load image at ' + url
    callback(new Error(msg))
  }
  image.src = url
}

export default loadImage

{{< /highlight >}}

Sama, mutta käytetty lupauksia:

{{< highlight javascript >}}

function loadImage(url) {
  return new Promise((resolve, reject) => {
    let image = new Image()
    image.onload = function() {
      resolve(image)
    }
    image.onerror = function () {
      let message = 'Could not load image at ' + url
      reject(new Error(msg))
    }
    image.src = url
  })
}

export default loadImage

{{< /highlight >}}

Takaisin ohjelmaan:

{{< highlight javascript >}}

let addImg = (src) => {
  let img = document.createElement("img")
  imgElement.src = src
  document.body.appendChild(imgElement)
}

loadImage('imges/cat1.jpg').then((img1 => {
  addImg(img1.src)
  loadImage('images/cat2.jpg').then(img2 => {
    addImg(img2.src)
    loadImage('imges/cat3.jpg').then(img3 => {
      addImg(img3.src)
    })
  })
})

{{< /highlight >}}

Kehitetään vielä eteenpäin komposioimalla:

{{< highlight javascript >}}

let addImg = (src) => {
  let img = document.createElement("img")
  imgElement.src = src
  document.body.appendChild(imgElement)
}

Promise.all([
  loadImage('images/cat1.jpg'),
  loadImage('images/cat2.jpg'),
  loadImage('images/cat3.jpg')
  ]).then(imgs => {
    images.forEach(img => addImg(img.src))
  }).catch(error => {
    // handle errors 
  })

{{< /highlight >}}

### Funktorit

{{< highlight javascript >}}

function plus1(value) {
  return value + 1
}

console.log(plus1(3))
console.log(plus1([3, 4]))

{{< /highlight >}}

Ensimmäinen `console.log` toimii, mutta jälkimmäinen ei. Se voidaan korjata muuttamalla kirjoittamalla funktio uudelleen.

{{< highlight javascript >}}

function plus1(value) {
  if (Array.isArray(value)) {
    let newArray = []
    for (let i = 0; i < value.length; i++) {
      newArray[i] = value[i] + 1
    }
    return newArray
  }
  return value + 1
}

console.log(plus1([3, 4]))

{{< /highlight >}}

Mutta jos nyt halutaan, että argumenttiksi voidaan antaa kirjaimia, esimerkiksi `plus1('ABC')`, olisi funktioon taas tehtävä muutos. Esimerkiksi taulun laskeminen olisi voitu ratkaista tällä tavalla:

{{< highlight javascript >}}

function plus1(value) {
  return value + 1
}

[3,4].map(plus1)

{{< /highlight >}}

Tällä ei kuitenkaan ratkaista `plus1('ABC')` ongelmaa. Luodaan `stringFunctor`:

{{< highlight javascript >}}

function stringFunctor(value, fn) {
  let chars = value.split("")
  return chars.map(function(char) {
    return String.fromCharCode(fn(char.charCodeAt(0)))
  }).join("")
}

function plus1(value) {
  return value + 1
}

function minus1(value) {
  return value - 1
}

[3,4].map(plus1)  // returns [4, 5]
stringFunctor('ABC', plus1)
stringFunctor('XYZ', minus1)

{{< /highlight >}}

## Lähteet

[^1]: https://www.youtube.com/watch?v=sjyJBL5fkp8
[^2]: https://www.youtube.com/watch?v=6sQDTgOqh-I 
[^3]: https://www.youtube.com/watch?v=BMUiFMZr7vk&list=PL0zVEGEvSaeEd9hlmCXrk5yUyqUag-n84&index=1
[^4]: https://www.youtube.com/watch?v=Mus_vwhTCq0
