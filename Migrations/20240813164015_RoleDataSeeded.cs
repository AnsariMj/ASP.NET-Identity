using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace UserManagement.API.Migrations
{
    /// <inheritdoc />
    public partial class RoleDataSeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "b1506ea0-0edd-4808-bf34-79ec967a22fb", "1", "Admin", "Admin" },
                    { "e4a4fa6c-3ee2-45c8-91e0-8bfd758fa372", "2", "User", "User" },
                    { "fb562890-8e92-4192-aa17-15ea0759447b", "3", "HR", "HR" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "b1506ea0-0edd-4808-bf34-79ec967a22fb");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e4a4fa6c-3ee2-45c8-91e0-8bfd758fa372");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "fb562890-8e92-4192-aa17-15ea0759447b");
        }
    }
}
