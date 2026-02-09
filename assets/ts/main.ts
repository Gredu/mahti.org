const displays: any = {
  blogit: false,
  muistiinpanoja: false,
  kirjoittajat: false,
};

(window as any).displayMenu = function(groupId: string) {
  const main = document.getElementById('main')
  const groups = document.querySelectorAll('.groups')

  if (!main) return

  function setDisplaysFalse() {
    for (const k in displays) {
      displays[k] = false
    }
  }

  function setOpacity(elements: NodeListOf<Element>, opacity: string) {
    elements.forEach((el) => {
      (el as HTMLElement).style.opacity = opacity
    });
  }

  function setAllOpacityZero() {
    document.querySelectorAll('.group-card').forEach((e) => {
      (e as HTMLElement).style.opacity = "0"
    })
  }

  function setTransitionY() {
    const activeGroups = Object.keys(displays).filter(k => displays[k])
    if (activeGroups.length === 1) {
      const target = document.getElementById(activeGroups[0])
      if (target) {
        main!.style.transform = `translateY(${target.offsetHeight}px)`
      }
    } else {
      main!.style.transform = 'translateY(0)'
    }
  }

  function setZindex() {
    const el = document.getElementById(groupId)
    if (el) el.style.zIndex = "0"
  }

  function reset() {
    setOpacity(document.querySelectorAll('.group-card'), "0")
    groups.forEach((g) => {
      (g as HTMLElement).style.zIndex = "-1"
    });
  }

  function renderDisplay() {
    reset()
    setTransitionY()
    setZindex()
    setOpacity(document.querySelectorAll(`#${groupId} .group-card`), "1")
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
