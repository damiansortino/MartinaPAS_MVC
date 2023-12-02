using MartinaPAS_MVC.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

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

                        
                        
                        using (MartinaPASEntities DB = new MartinaPASEntities())
                        {
                            var sessionsToClose = DB.Sesiones
                            .Where(x => x.Id_Usuario == user.Id_Usuario && x.Fecha_Hora_Final == null)
                            .ToList();

                            foreach (var session in sessionsToClose)
                            {
                                session.Fecha_Hora_Final = DateTime.Now;
                            }

                            DB.SaveChanges();
                            
                        }
                        
                        FormsAuthentication.SetAuthCookie(user.Email, false);
                        Session["Usuario"] = user;

                        Sesiones sesion = new Sesiones();
                        sesion.Fecha_Hora_Inicio = DateTime.Now;
                        sesion.Direccion_IP = GetClientIpAddress(Request);
                        sesion.Id_Usuario = user.Id_Usuario;

                        //detecion de dispositivo

                        string userAgent = Request.UserAgent;

                        // Realizar análisis del User-Agent para determinar el tipo de dispositivo
                        string deviceType = "Desconocido";

                        if (userAgent != null && userAgent.ToLower().Contains("mobile"))
                        {
                            deviceType = "Dispositivo Móvil";
                        }
                        else if (userAgent != null && userAgent.ToLower().Contains("tablet"))
                        {
                            deviceType = "Tablet";
                        }
                        else if (userAgent != null && userAgent.ToLower().Contains("windows"))
                        {
                            deviceType = "Windows";
                        }
                        else if (userAgent != null && userAgent.ToLower().Contains("linux"))
                        {
                            deviceType = "Linux";
                        }
                        sesion.Tipo_Dispositivo = deviceType;

                        using (MartinaPASEntities DB = new MartinaPASEntities())
                        {
                            DB.Sesiones.Add(sesion);
                            DB.SaveChanges();
                        }


                        return RedirectToAction("Index", "Home"); // Cambia "Home" por tu controlador y acción deseados
                    }
                }
            }

            // Si las credenciales son inválidas o no se encuentran, muestra un mensaje de error
            ViewBag.ErrorMessage = "Credenciales inválidas. Por favor, intenta nuevamente.";
            return View();
        }

        public ActionResult CerrarSesion()
        {
            try
            {
                using (MartinaPASEntities DB = new MartinaPASEntities())
                {
                    Usuarios user = (Usuarios)Session["Usuario"];

                    Sesiones ultimaSesion = DB.Sesiones
                    .Where(s => s.Id_Usuario == user.Id_Usuario)
                    .OrderByDescending(s => s.Fecha_Hora_Inicio)
                    .FirstOrDefault();

                    ultimaSesion.Fecha_Hora_Final = DateTime.Now;
                    DB.SaveChanges();
                }
                FormsAuthentication.SignOut();
                Session["Usuario"] = null;

                return RedirectToAction("Index", "Login");
            }
            catch (Exception ex)
            {
                ViewBag.ErrorMessage = ex.Message;
                return RedirectToAction("Index", "Login");
            }   
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

        private string GetClientIpAddress(HttpRequestBase request)
        {
            string ipAddress = request.ServerVariables["HTTP_X_FORWARDED_FOR"];

            if (string.IsNullOrEmpty(ipAddress))
            {
                ipAddress = request.UserHostAddress;
            }

            return ipAddress;
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