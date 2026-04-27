// app/static/js/utils/modals.js
// Generic modal show/hide/toggle. Replaces the 4+ near-identical pairs of
// `modal.classList.remove('hidden')` / `add('hidden')` across base.js,
// results.js, upload.js, holygrail.js.

export class Modal {
    constructor(modalId) {
        this.id = modalId;
        this.modal = document.getElementById(modalId);
    }

    get exists() { return this.modal !== null && this.modal !== undefined; }

    show() { this.modal?.classList.remove('hidden'); }
    hide() { this.modal?.classList.add('hidden'); }
    toggle() { this.modal?.classList.toggle('hidden'); }

    // Click outside the dialog body dismisses the modal.
    bindBackdropDismiss() {
        if (!this.exists) return this;
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) this.hide();
        });
        return this;
    }
}

// Bind a single Escape-key handler that hides any of the given modals.
export function bindEscapeToHide(modals) {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') modals.forEach((m) => m && m.hide && m.hide());
    });
}
