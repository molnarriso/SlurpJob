using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SlurpJob.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "IncidentLog",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Timestamp = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false),
                    CountryCode = table.Column<string>(type: "TEXT", nullable: false),
                    TargetPort = table.Column<int>(type: "INTEGER", nullable: false),
                    Protocol = table.Column<string>(type: "TEXT", nullable: false),
                    PayloadProtocol = table.Column<string>(type: "TEXT", nullable: false),
                    Intent = table.Column<string>(type: "TEXT", nullable: false),
                    ClassifierName = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IncidentLog", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EvidenceLocker",
                columns: table => new
                {
                    IncidentId = table.Column<long>(type: "INTEGER", nullable: false),
                    PayloadBlob = table.Column<byte[]>(type: "BLOB", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EvidenceLocker", x => x.IncidentId);
                    table.ForeignKey(
                        name: "FK_EvidenceLocker_IncidentLog_IncidentId",
                        column: x => x.IncidentId,
                        principalTable: "IncidentLog",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_IncidentLog_Timestamp",
                table: "IncidentLog",
                column: "Timestamp");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EvidenceLocker");

            migrationBuilder.DropTable(
                name: "IncidentLog");
        }
    }
}
