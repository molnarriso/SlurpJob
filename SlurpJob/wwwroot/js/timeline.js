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
                            const index = legendItem.datasetIndex;
                            const ci = legend.chart;
                            const count = ci.data.datasets.length;

                            // Helper to check if a specific dataset is strictly the only one visible/hidden
                            // Note: chart.js methods: isDatasetVisible(i), setDatasetVisibility(i, bool), update()

                            let visibleCount = 0;
                            for (let i = 0; i < count; i++) {
                                if (ci.isDatasetVisible(i)) visibleCount++;
                            }

                            const isCurrentVisible = ci.isDatasetVisible(index);

                            // State 1: All Visible (Initial)
                            const isAllVisible = visibleCount === count;

                            // State 2: Only Current Visible (Exclusive)
                            const isOnlyCurrentVisible = visibleCount === 1 && isCurrentVisible;

                            // State 3: Only Current Hidden (Filtered)
                            const isOnlyCurrentHidden = visibleCount === count - 1 && !isCurrentVisible;

                            if (isAllVisible) {
                                // Transition to: Only Current Visible
                                for (let i = 0; i < count; i++) {
                                    ci.setDatasetVisibility(i, i === index);
                                }
                            } else if (isOnlyCurrentVisible) {
                                // Transition to: Only Current Hidden (Filter out just this one)
                                for (let i = 0; i < count; i++) {
                                    ci.setDatasetVisibility(i, i !== index);
                                }
                            } else if (isOnlyCurrentHidden) {
                                // Transition to: All Visible (Reset)
                                for (let i = 0; i < count; i++) {
                                    ci.setDatasetVisibility(i, true);
                                }
                            } else {
                                // Transition to: Only Current Visible (Catch-all for switching from one exclusive to another)
                                for (let i = 0; i < count; i++) {
                                    ci.setDatasetVisibility(i, i === index);
                                }
                            }

                            ci.update();
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

            // Preserve visibility state
            const visibilityMap = {};
            if (chart.data && chart.data.datasets) {
                chart.data.datasets.forEach((ds, index) => {
                    // isDatasetVisible handles the logic of whether it's shown or not
                    visibilityMap[ds.label] = chart.isDatasetVisible(index);
                });
            }

            chart.data = newData;

            // Restore visibility state
            if (chart.data.datasets) {
                chart.data.datasets.forEach((ds) => {
                    if (visibilityMap.hasOwnProperty(ds.label)) {
                        ds.hidden = !visibilityMap[ds.label];
                    }
                });
            }

            chart.update('none'); // Update without animation for performance
        } catch (e) {
            console.error('Timeline update error:', e);
        }
    }
};
