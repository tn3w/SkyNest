document.addEventListener('DOMContentLoaded', () => {
    const noscriptInput = document.getElementById('noscript-input');

    if (noscriptInput) {
        noscriptInput.remove();
    }
    
    const inputs = document.querySelectorAll('.code-input');
    inputs[0].focus();

    const form = document.getElementById("form");
    const submitButton = document.getElementById("button");

    const areAllInputsFilled = () => {
        return Array.from(inputs).every(input => input.value.trim() !== '');
    };

    const toggleSubmitButton = () => {
        submitButton.disabled = !areAllInputsFilled();
    };

    const gatherInputValues = () => {
        const code = Array.from(inputs).map(input => input.value).join('');
        const hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'codes';
        hiddenInput.value = code;
        form.appendChild(hiddenInput);
    };

    inputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            const value = e.target.value;
            if (/^\d$/.test(value)) {
                e.target.value = value;
                if (index < inputs.length - 1) {
                inputs[index + 1].focus();
                }
            } else {
                e.target.value = '';
            }
            toggleSubmitButton();
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && e.target.value === '' && index > 0) {
                const previousInput = inputs[index - 1];
                previousInput.focus();
                previousInput.setSelectionRange(previousInput.value.length, previousInput.value.length);
            }
        });

        input.addEventListener('paste', (e) => {
            const pasteData = e.clipboardData.getData('text');
            const digits = pasteData.match(/\d/g); // Extract digits
            if (digits) {
                let cursor = 0;
                for (let i = index; i < inputs.length && cursor < digits.length; i++) {
                    inputs[i].value = digits[cursor++];
                }
                if (cursor < digits.length) {
                    for (let i = 0; i < index && cursor < digits.length; i++) {
                        inputs[i].value = digits[cursor++];
                    }
                }
            }
            e.preventDefault();
            toggleSubmitButton();
        });
    });

    submitButton.addEventListener('click', () => {
        if (areAllInputsFilled()) {
          gatherInputValues();
          form.submit();
        }
    });
});