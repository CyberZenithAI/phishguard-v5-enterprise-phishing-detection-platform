// static/js/widgets/ioc_table.js

export class IOCTableWidget {

    constructor(containerId, telemetry) {

        this.container = document.getElementById(containerId);
        this.telemetry = telemetry;

        this.rows = [];
    }

    initialize() {

        this.telemetry.subscribe(
            "ioc",
            (payload) => this.addIOC(payload.data)
        );

        document
            .getElementById("iocSearch")
            .addEventListener(
                "input",
                this.debounce(
                    (event) => this.search(event.target.value),
                    300
                )
            );

        document
            .getElementById("exportCSV")
            .addEventListener(
                "click",
                () => this.exportCSV()
            );

        document
            .getElementById("exportJSON")
            .addEventListener(
                "click",
                () => this.exportJSON()
            );
    }

    addIOC(ioc) {

        this.rows.unshift(ioc);

        this.render(this.rows);
    }

    render(rows) {

        this.container.innerHTML = "";

        const fragment = document.createDocumentFragment();

        for (const row of rows.slice(0, 100)) {

            const tr = document.createElement("tr");

            tr.innerHTML = `
                <td>${row.observable}</td>
                <td>${row.type}</td>
                <td>${row.score}</td>
                <td>${row.source}</td>
                <td>
                    <button data-copy="${row.observable}">
                        Copy
                    </button>
                </td>
            `;

            fragment.appendChild(tr);
        }

        this.container.appendChild(fragment);

        this.attachCopyHandlers();
    }

    attachCopyHandlers() {

        document.querySelectorAll("[data-copy]").forEach((button) => {

            button.onclick = async () => {

                await navigator.clipboard.writeText(
                    button.dataset.copy
                );

            };
        });
    }

    search(query) {

        const filtered = this.rows.filter((item) =>
            item.observable.includes(query)
        );

        this.render(filtered);
    }

    exportCSV() {

        const csv = this.rows
            .map(
                (r) =>
                    `${r.observable},${r.type},${r.score},${r.source}`
            )
            .join("\n");

        this.download(csv, "iocs.csv", "text/csv");
    }

    exportJSON() {

        this.download(
            JSON.stringify(this.rows, null, 2),
            "iocs.json",
            "application/json"
        );
    }

    download(content, filename, mime) {

        const blob = new Blob([content], { type: mime });

        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");

        a.href = url;
        a.download = filename;
        a.click();

        URL.revokeObjectURL(url);
    }

    debounce(fn, wait) {

        let timeout;

        return (...args) => {

            clearTimeout(timeout);

            timeout = setTimeout(
                () => fn(...args),
                wait
            );
        };
    }
}
