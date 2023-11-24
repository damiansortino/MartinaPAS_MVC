using MartinaPAS_MVC.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace MartinaPAS_MVC.Controllers
{
    public class LoginController : Controller
    {
        private readonly MartinaPASEntities _dbContext; // Asegúrate de tener acceso a tu DbContext

        public LoginController()
        {
            _dbContext = new MartinaPASEntities(); // Inicializa tu DbContext aquí
        }

        // GET: Login
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(string username, string password)
        {
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                // Busca al usuario por el nombre de usuario en la base de datos
                var user = _dbContext.Usuarios.FirstOrDefault(u => u.Username == username);

                if (user != null)
                {
                    // Verifica la contraseña utilizando SHA256
                    string hashedPassword = HashPassword(password);

                    // Compara la contraseña hasheada con la contraseña almacenada en la base de datos
                    if (user.Password == hashedPassword)
                    {
                        // Autenticación exitosa, puedes redirigir a la página de inicio o a la página deseada
                        return RedirectToAction("Index", "Home"); // Cambia "Home" por tu controlador y acción deseados
                    }
                }
            }

            // Si las credenciales son inválidas o no se encuentran, muestra un mensaje de error
            ViewBag.ErrorMessage = "Credenciales inválidas. Por favor, intenta nuevamente.";
            return View();
        }

        // Método para hashear la contraseña utilizando SHA256
        private string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _dbContext.Dispose(); // Libera el contexto de base de datos
            }
            base.Dispose(disposing);
        }
    }
}