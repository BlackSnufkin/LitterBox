// app/static/js/utils/dom.js
// Tiny DOM helpers — reduce `document.getElementById`/`querySelector` noise
// in the renderer modules.

export const qs = (selector, root = document) => root.querySelector(selector);
export const qsa = (selector, root = document) =>
    Array.from(root.querySelectorAll(selector));

// Build an element with attrs and children.
//   el('div', {class: 'foo', onclick: handler}, ['hello', el('span', {}, ['world'])])
export function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
        if (value === null || value === undefined) continue;
        if (key === 'class' || key === 'className') {
            node.className = value;
        } else if (key === 'style' && typeof value === 'object') {
            Object.assign(node.style, value);
        } else if (key === 'dataset' && typeof value === 'object') {
            for (const [dk, dv] of Object.entries(value)) node.dataset[dk] = dv;
        } else if (key.startsWith('on') && typeof value === 'function') {
            node.addEventListener(key.slice(2).toLowerCase(), value);
        } else {
            node.setAttribute(key, value);
        }
    }
    const list = Array.isArray(children) ? children : [children];
    for (const child of list) {
        if (child === null || child === undefined || child === false) continue;
        node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    return node;
}

// Replace innerHTML with built nodes (or HTML string).
export function replaceContent(parent, content) {
    if (!parent) return;
    if (typeof content === 'string') {
        parent.innerHTML = content;
    } else if (Array.isArray(content)) {
        parent.replaceChildren(...content);
    } else if (content) {
        parent.replaceChildren(content);
    } else {
        parent.replaceChildren();
    }
}
