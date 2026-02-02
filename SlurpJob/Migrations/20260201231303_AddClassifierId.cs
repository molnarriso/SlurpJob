using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SlurpJob.Migrations
{
    /// <inheritdoc />
    public partial class AddClassifierId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ClassifierId",
                table: "IncidentLog",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ClassifierId",
                table: "IncidentLog");
        }
    }
}
