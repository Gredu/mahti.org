const displays = {
  blogit: false,
  muistiinpanoja: false,
  kirjoittajat: false,
}

function displayMenu(groupId: string) {

  const main = document.getElementById('main')
  const groups = document.querySelectorAll('.groups')

  function setDisplaysFalse(): void {
    Object.keys(displays).forEach(k => {
      displays[k] = false
    })
  }

  function setOpacity(elements: NodeListOf<Element>, opacity: string): void {
    for (let i = 0; i < elements.length; i++) {
      (elements[i] as HTMLElement).style.opacity = opacity
    }
  }

  function setAllOpacityZero(): void {
    document.querySelectorAll('.group-card').forEach(e => {
      (e as HTMLElement).style.opacity = "0"
    })
  }

  function setTransitionY(): void {
    const displayTarget = Object.keys(displays).filter(k => displays[k] == true)
    if (displayTarget.length == 1) {
      const offsetHeight = document.getElementById(displayTarget[0]).offsetHeight + "px"
      main.style.transform = `translateY(${offsetHeight})`
    } else {
      main.style.transform = 'translateY(0)'
    }
  }

  function setZindex(): void {
    document.getElementById(groupId).style.zIndex = "0"
  }

  function reset(): void {
    const hideLists = document.querySelectorAll('.group-card')
    setOpacity(hideLists, "0");
    for (let i = 0; i < groups.length; i++) {
      (groups[i] as HTMLElement).style.zIndex = "-1"
    }
  }

  function renderDisplay() :void {
    reset()
    setTransitionY()
    setZindex()

    const showList = document.querySelectorAll(`#${groupId} .group-card`)
    setOpacity(showList, "1")
  }

  if (displays[groupId]) {
    setDisplaysFalse()
    renderDisplay()
    setAllOpacityZero()
  } else {
    setDisplaysFalse()
    displays[groupId] = true
    renderDisplay()
  }

}
