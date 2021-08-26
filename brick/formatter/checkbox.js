function do_strikethrough(checkbox, id)
{
    elem = document.getElementById(`li_${id}`)
    if (checkbox.checked == true) {
        elem.innerHTML = elem.innerText.strike()
    } else {
        elem.innerHTML = elem.innerText
    }

    console.debug(`Setting ${id} to ${checkbox.checked}`)
    localStorage.setItem(id, checkbox.checked)
}

function init()
{
    for (let id = 0; ; id++) {
        elem = document.getElementById(`li_${id}`);
        if (elem == null) break;
        
        console.debug(`${id} is ${localStorage.getItem(id)}`);
        if (localStorage.getItem(id) == 'true') {
            elem.innerHTML = elem.innerText.strike();
            checkbox = document.getElementById(`checkbox_${id}`);
            checkbox.checked = true;
        } else {
            elem.innerHTML = elem.innerText
            // checkbox.value = false;
        }
    }
}