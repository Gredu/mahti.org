---
title: "vue"
author: "Greatman Lim"
muistiinpanoja: ["Ohjelmointi"]
---

Muistiinpanoja vuesta samalla kun sitä opiskelen. Yliopistolla tuli jo vähän tutustuttua angulariin, mutta mielestäni se on jäämässä reactin ja vuen jalkoihin.

## Perusteet [^1]

Vue voidaan asentaa monella eri tavalla. Tässä javascript ja html on eristettynä, ja vuen käyttöä esitellään eri tavoilla.

HTML:

{{< highlight html >}}

<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width" />
    <title>Vue</title>
    <script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
  </head>
  <body>

    <div id="app">
      {{ message }}
    </div>

    <div id="bind">
      <span v-bind:title="message">
      <!-- v-bind luo atribuutin ja sille arvon  -->
        Binding app
      </span>
    </div>

    <div id="seen">
      <span v-if="seen">Now you see me</span>
    </div>

    <div id="loop">
      <ol>
        <li v-for="todo in todos">
          {{ todo.text }}
        </li>
      </ol>
    </div>

    <div id="clicky">
      <p>{{ message }}</p>
      <button v-on:click="reverseMessage">Reverse Message</button>
    </div>

    <div id="model">
      <p>{{ message }}</p>
      <input v-model="message">
    </div>

    <script src="index.js"></script>

  </body>
</html>

{{< /highlight >}}

javascript:

{{< highlight javascript >}}

let app = new Vue({
  el: '#app',
  data: {
    message: 'Hello Vue!'
  }
})

let binding = new Vue({
  el: '#bind',
  data: {
    message: 'You loaded this page on ' + new Date().toLocaleString()
  }
})

let seen = new Vue({
  el: '#seen',
  data: {
    seen: true
  }
})

let forloop = new Vue({
  el: '#loop',
  data: {
    todos: [
      { text: 'Learn JavaScript' },
      { text: 'Learn Vue' },
      { text: 'Build something awesome' }
    ]
  }
})

let clicky = new Vue({
  el: '#clicky',
  data: {
    message: 'Hello Vue.js'
  },
  methods: {
    reverseMessage: function () {
      this.message = this.message.split('').reverse().join('')
    }
  }
})

let model = new Vue({
  el: '#model',
  data: {
    message: 'foo'
  }
})

{{< /highlight >}}

## Komponentit ja props

Propsien avulla syötetään arvoja komponenteille.

{{< highlight html >}}

<ol id="app">
  <todo-item
    v-for="item in groceryList"
    v-bind:todo="item"
    v-bind:key="item.id"
  ></todo-item>
</ol>

{{< /highlight >}}

{{< highlight javascript >}}

Vue.component('todo-item', {
  props: ['todo'],
  template: '<li>{{ todo.text }}</li>'
})

let app = new Vue({
  el: '#app',
  data: {
    groceryList: [
      { id: 1, text: 'First title' },
      { id: 2, text: 'Journey to be nerd' },
      { id: 3, text: 'Are we there yet?' }
    ]
  }
})

{{< /highlight >}}

## Lähteet

[^1]: https://vuejs.org/v2/guide/
