/*
 * Imperva IOC Block - table cell renderer for the detections table (id="det_table").
 * "Block / Allow" (WAF requests, last 24 h) and "Web Block / Allow" (websites):
 * the block number is shown red, the allow number green, e.g. 500 / 18.
 */
require([
    "splunkjs/mvc",
    "splunkjs/mvc/tableview",
    "splunkjs/mvc/simplexml/ready!"
], function (mvc, TableView) {
    var FIELDS = { "Block / Allow": true, "Web Block / Allow": true };

    var BlockAllowRenderer = TableView.BaseCellRenderer.extend({
        canRender: function (cell) {
            return FIELDS.hasOwnProperty(cell.field);
        },
        render: function ($td, cell) {
            var parts = String(cell.value === null || cell.value === undefined ? "" : cell.value).split("/");
            $td.empty().css("white-space", "nowrap");
            if (parts.length !== 2) {
                $td.text(cell.value === null || cell.value === undefined ? "" : String(cell.value));
                return;
            }
            var block = document.createElement("span");
            block.textContent = parts[0].trim();
            block.style.color = "#DC4E41";
            block.style.fontWeight = "bold";
            var allow = document.createElement("span");
            allow.textContent = parts[1].trim();
            allow.style.color = "#53A051";
            allow.style.fontWeight = "bold";
            $td.append(block, document.createTextNode(" / "), allow);
        }
    });

    var table = mvc.Components.get("det_table");
    if (table) {
        table.getVisualization(function (view) {
            view.addCellRenderer(new BlockAllowRenderer());
            view.render();
        });
    }
});
