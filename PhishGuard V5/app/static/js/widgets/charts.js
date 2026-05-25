// static/js/widgets/charts.js

export class ChartsManager {

    constructor(telemetry) {

        this.telemetry = telemetry;
    }

    initialize() {

        this.initializeSPF();
        this.initializeDKIM();
        this.initializeLatency();
        this.initializeTimeline();
    }

    initializeSPF() {

        this.spfChart = new ApexCharts(
            document.querySelector("#spfChart"),
            {
                chart: {
                    type: "line",
                    height: 250
                },
                series: [{
                    name: "SPF Failures",
                    data: []
                }],
                xaxis: {
                    type: "datetime"
                }
            }
        );

        this.spfChart.render();

        this.telemetry.subscribe(
            "spf_failures",
            (payload) => {

                this.spfChart.updateSeries([{
                    data: payload.data
                }]);

            }
        );
    }

    initializeDKIM() {

        this.dkimChart = new ApexCharts(
            document.querySelector("#dkimChart"),
            {
                chart: {
                    type: "area",
                    height: 250
                },
                series: [{
                    name: "DKIM Failures",
                    data: []
                }]
            }
        );

        this.dkimChart.render();
    }

    initializeLatency() {

        this.latencyChart = new ApexCharts(
            document.querySelector("#latencyChart"),
            {
                chart: {
                    type: "line",
                    animations: {
                        enabled: true
                    }
                },
                series: [{
                    name: "p95",
                    data: []
                }]
            }
        );

        this.latencyChart.render();
    }

    initializeTimeline() {

        this.timelineChart = new ApexCharts(
            document.querySelector("#timelineChart"),
            {
                chart: {
                    type: "bar"
                },
                series: [{
                    data: []
                }]
            }
        );

        this.timelineChart.render();
    }
}
