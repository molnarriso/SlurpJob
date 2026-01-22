window.slurpTimeline = {
    charts: {},

    init: async function (canvasId, dotNetRef) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error('Timeline canvas not found:', canvasId);
            return;
        }

        // Get initial data from Blazor
        const chartData = await dotNetRef.invokeMethodAsync('GetChartData');

        this.charts[canvasId] = new Chart(ctx, {
            type: 'bar',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false, // Disable animation for snappy "app-like" feel
                scales: {
                    x: {
                        stacked: true,
                        ticks: { color: '#adb5bd' },
                        grid: { color: '#495057' }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        ticks: { color: '#adb5bd' },
                        grid: { color: '#495057' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#adb5bd' },
                        onClick: function (e, legendItem, legend) {
                            // Dumb View: Just report the click to C#
                            const label = legendItem.text;
                            dotNetRef.invokeMethodAsync('OnClassifierClicked', label);
                        }
                    }
                }
            }
        });

        // Store dotNetRef for updates
        this.charts[canvasId].dotNetRef = dotNetRef;
    },

    update: async function (canvasId) {
        const chart = this.charts[canvasId];
        if (!chart || !chart.dotNetRef) return;

        try {
            const newData = await chart.dotNetRef.invokeMethodAsync('GetChartData');
            chart.data = newData;
            chart.update('none');
        } catch (e) {
            console.error('Timeline update error:', e);
        }
    },

    // New method called by C# to enforce visual state
    updateVisuals: function (canvasId, hiddenLabels) {
        const chart = this.charts[canvasId];
        if (!chart) return;

        let changed = false;
        chart.data.datasets.forEach((ds, index) => {
            const shouldHide = hiddenLabels.includes(ds.label);
            if (chart.isDatasetVisible(index) === shouldHide) {
                chart.setDatasetVisibility(index, !shouldHide);
                changed = true;
            }
        });

        if (changed) {
            chart.update('none');
        }
    }
};

// Global orchestrator for synchronizing updates if needed, though C# calls specific modules
window.slurp = window.slurp || {};
window.slurp.updateVisuals = function (visuals) {
    // visuals = { timeline: [hiddenLabels], map: { activeCountry: '...', mode: '...' } }

    if (visuals.timeline && window.slurpTimeline) {
        window.slurpTimeline.updateVisuals('timelineChart', visuals.timeline);
    }

    if (visuals.map && window.slurpMap2D) {
        window.slurpMap2D.updateVisuals(visuals.map);
    }
};
