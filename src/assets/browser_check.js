class ProofOfWorkClient {
    constructor(workerCount = navigator.hardwareConcurrency || 4) {
        this.workerCount = workerCount;
        this.workers = [];
        this.currentSolutions = new Map();
    }

    startWorkers(salt, difficulty, form) {
        if (this.currentSolutions.has(salt)) {
            console.warn(`Task with string "${salt}" is already being solved.`);
            return;
        }

        const prefix = "0".repeat(difficulty);
        let solutionFound = false;

        this.workers = Array.from({ length: this.workerCount }, (_, index) => {
            const worker = new Worker(
                URL.createObjectURL(
                    new Blob([
                        `
                const calculateHash = async (input) => {
                    const buffer = new TextEncoder().encode(input);
                    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
                    return Array.from(new Uint8Array(hashBuffer))
                        .map((byte) => byte.toString(16).padStart(2, '0'))
                        .join('');
                };

                self.onmessage = async function(e) {
                    const { salt, prefix, start, step, batchSize } = e.data;
                    let nonce = start;

                    while (true) {
                        for (let i = 0; i < batchSize; i++) {
                            const hash = await calculateHash(salt + nonce);
                            if (hash.startsWith(prefix)) {
                                self.postMessage(nonce);
                                return;
                            }
                            nonce += step;
                        }
                    }
                };
                `,
                    ])
                )
            );

            worker.onmessage = (e) => {
                if (!solutionFound) {
                    solutionFound = true;

                    this.workers.forEach((w) => w.terminate());

                    const nonce = e.data;
                    this.currentSolutions.set(salt, nonce);

                    const hiddenInput = document.createElement("input");
                    hiddenInput.type = "hidden";
                    hiddenInput.name = "pow_solution";
                    hiddenInput.value = nonce;
                    form.appendChild(hiddenInput);
                    form.submit();
                }
            };

            const batchSize = 1000;
            worker.postMessage({
                salt: salt,
                prefix,
                start: index,
                step: this.workerCount,
                batchSize,
            });

            return worker;
        });
    }

    getSolution(salt) {
        return this.currentSolutions.get(salt) || null;
    }
}

document.addEventListener("DOMContentLoaded", function() {
    const browserCheckForm = document.getElementById("browserCheckForm");
    const challenge = "{{ powbox_challenge }}";
    const powClient = new ProofOfWorkClient()
    powClient.startWorkers(challenge, 5, browserCheckForm);
});