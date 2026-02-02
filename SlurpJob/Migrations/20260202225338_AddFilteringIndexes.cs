using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SlurpJob.Migrations
{
    /// <inheritdoc />
    public partial class AddFilteringIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_AttackId",
                table: "IncidentLog",
                column: "AttackId");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_ClassifierName",
                table: "IncidentLog",
                column: "ClassifierName");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_CountryCode",
                table: "IncidentLog",
                column: "CountryCode");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_Intent",
                table: "IncidentLog",
                column: "Intent");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_TargetPort",
                table: "IncidentLog",
                column: "TargetPort");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_Timestamp_ClassifierName",
                table: "IncidentLog",
                columns: new[] { "Timestamp", "ClassifierName" });

            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_Timestamp_CountryCode",
                table: "IncidentLog",
                columns: new[] { "Timestamp", "CountryCode" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_IncidentLog_AttackId",
                table: "IncidentLog");

            migrationBuilder.DropIndex(
                name: "IX_IncidentLog_ClassifierName",
                table: "IncidentLog");

            migrationBuilder.DropIndex(
                name: "IX_IncidentLog_CountryCode",
                table: "IncidentLog");

            migrationBuilder.DropIndex(
                name: "IX_IncidentLog_Intent",
                table: "IncidentLog");

            migrationBuilder.DropIndex(
                name: "IX_IncidentLog_TargetPort",
                table: "IncidentLog");

            migrationBuilder.DropIndex(
                name: "IX_IncidentLog_Timestamp_ClassifierName",
                table: "IncidentLog");

            migrationBuilder.DropIndex(
                name: "IX_IncidentLog_Timestamp_CountryCode",
                table: "IncidentLog");
        }
    }
}
