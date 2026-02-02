using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SlurpJob.Migrations
{
    /// <inheritdoc />
    public partial class RefactorClassifierIds : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AttackId",
                table: "IncidentLog",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AttackId",
                table: "IncidentLog");
        }
    }
}
