console.log('Hello from Babel!')

const displays = {
  blogit: false,
  muistiinpanoja: false,
}

function displayMenu(elementId: string) {

  const cards = document.getElementsByClassName('group-card')
  for (let i = 0; i < cards.length; i++) {
    cards[i].classList.add('hidden')
  }

  const main = document.getElementById('main')
  const displayElement = document.getElementById(elementId)

  if (displays[elementId]) {
    const offsetHeight = displayElement.offsetHeight + "px"
    main.style.transform = `translateY(-${offsetHeight})`
    displays[elementId] = false
  } else {
    
    for (let i = 0; i < displayElement.children.length; i++) {
      displayElement.children[i].classList.remove('hidden')
    }

    const offsetHeight = displayElement.offsetHeight + "px"
    main.style.transform = `translateY(${offsetHeight})`

    Object.keys(displays).forEach(k => {
      displays[k] = displays[k] = false
    })

    displays[elementId] = true
  }
}
