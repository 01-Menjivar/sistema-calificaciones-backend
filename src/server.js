const http = require('http');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const path = require('path');
const dotenv = require('dotenv');
const { generarSalt, generarHashConSalt, extraerSalt } = require('./authHelpers');

dotenv.config({ path: path.join(__dirname, '../.env') });

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;

function verifyToken(req) {
    try {
        const bearerHeader = req.headers?.['authorization'];
        console.log('Bearer Header:', bearerHeader); // Debug

        if (!bearerHeader) {
            console.log('No se encontró el header de autorización');
            return null;
        }

        const token = bearerHeader.split(' ')[1];
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        console.error('Error al verificar token:', error);
        return null;
    }
}

// Funciones de utilidad para CORS y respuestas
function setCORSHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', 'http://127.0.0.1:5500');  // URL de tu frontend
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400');
}

function sendResponse(res, statusCode, data) {
    res.writeHead(statusCode, { 
        'Content-Type': 'application/json'
    });
    res.end(JSON.stringify(data));
}

// Configuración de conexión a la base de datos MySQL
const connection = mysql.createConnection({
    host: '127.0.0.1',
    user: 'usuario',          
    password: 'contraseña',    
    database: 'sistema_calificaciones',
    port: 3306
});

// Conexión a la base de datos con mejor manejo de errores
connection.connect((err) => {
    if (err) {
        console.error('Error detallado de conexión a MySQL:');
        console.error('Error code:', err.code);
        console.error('Error estado:', err.sqlState);
        console.error('Error mensaje:', err.message);
        console.error('Error stack:', err.stack);
        return;
    }
    console.log('Conectado a la base de datos MySQL.');
});

// Agregar listener para errores de conexión
connection.on('error', (err) => {
    console.error('Error de MySQL:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.error('Se perdió la conexión con la base de datos');
    } else if (err.code === 'ER_CON_COUNT_ERROR') {
        console.error('La base de datos tiene demasiadas conexiones');
    } else if (err.code === 'ECONNREFUSED') {
        console.error('La conexión fue rechazada');
    }
});

/** FUNCIONES GENERALES **/

// Función de Registro de Usuario (General)
function registerUser(body, res) {
    const { nombre, email, contraseña } = JSON.parse(body);
    const rol = "estudiante";
    
    const salt = generarSalt();
    const hash = salt + generarHashConSalt(contraseña, salt);

    const query = 'INSERT INTO Usuarios (nombre, email, contraseña, rol) VALUES (?, ?, ?, ?)';
    connection.query(query, [nombre, email, hash, rol], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al registrar el estudiante' });
            return;
        }
        sendResponse(res, 201, { 
            message: 'Estudiante registrado con éxito', 
            userId: result.insertId 
        });
    });
}

// Función de Inicio de Sesión (General)
function loginUser(body, res) {
    const { email, contraseña } = JSON.parse(body);

    const query = 'SELECT id, nombre, rol, contraseña FROM Usuarios WHERE email = ?';
    connection.query(query, [email], (err, results) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al buscar usuario' });
            return;
        }

        if (results.length === 0) {
            sendResponse(res, 404, { error: 'Usuario no encontrado' });
            return;
        }

        const user = results[0];
        const storedHash = user.contraseña;
        const salt = extraerSalt(storedHash);
        const inputHash = salt + generarHashConSalt(contraseña, salt);

        if (inputHash === storedHash) {
            const token = jwt.sign(
                {
                    id: user.id,
                    nombre: user.nombre,
                    rol: user.rol
                },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN }
            );

            sendResponse(res, 200, {
                message: 'Inicio de sesión exitoso',
                token,
                user: {
                    id: user.id,
                    nombre: user.nombre,
                    rol: user.rol
                }
            });
        } else {
            sendResponse(res, 401, { error: 'Credenciales incorrectas' });
        }
    });
}

/** FUNCIONES PARA SUPER-ADMIN **/

function registerallkindausers(body, res) {
    const { nombre, email, contraseña, rol } = JSON.parse(body);

    const salt = generarSalt();
    const hash = salt + generarHashConSalt(contraseña, salt);

    const query = 'INSERT INTO Usuarios (nombre, email, contraseña, rol) VALUES (?, ?, ?, ?)';
    connection.query(query, [nombre, email, hash, rol], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al registrar el usuario' });
            return;
        }
        sendResponse(res, 201, { 
            message: 'Usuario registrado con éxito', 
            userId: result.insertId 
        });
    });
}

function listusers(req, res) {
    console.log('Headers en listusers:', req.headers);
    
    const verified = verifyToken(req);
    console.log('Token verificado:', verified);

    if (!verified || verified.rol !== 'director') {
        console.log('Acceso denegado. Rol:', verified?.rol);
        sendResponse(res, 401, { error: 'No autorizado' });
        return;
    }

    const query = 'SELECT id, nombre, email, rol FROM Usuarios WHERE rol != "director"';
    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error en la consulta:', err);
            sendResponse(res, 500, { error: 'Error al obtener la lista de usuarios' });
            return;
        }
        console.log('Resultados encontrados:', results.length);
        sendResponse(res, 200, results);
    });
}

function deleteStudent(studentId, res) {
    const query = 'DELETE FROM Usuarios WHERE id = ? AND rol = "estudiante"';
    connection.query(query, [studentId], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al eliminar al alumno' });
            return;
        }
        sendResponse(res, 200, { message: 'Alumno eliminado con éxito' });
    });
}

function deleteProfessor(professorId, res) {
    const query = 'DELETE FROM Usuarios WHERE id = ? AND rol = "profesor"';
    connection.query(query, [professorId], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al eliminar al profesor' });
            return;
        }
        sendResponse(res, 200, { message: 'Profesor eliminado con éxito' });
    });
}

function editStudent(studentId, body, res) {
    const { nombre, contraseña, email } = JSON.parse(body);
    const query = 'UPDATE Usuarios SET nombre = ?, contraseña = ?, email = ? WHERE id = ? AND rol = "estudiante"';
    connection.query(query, [nombre, contraseña, email, studentId], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al editar al alumno' });
            return;
        }
        sendResponse(res, 200, { message: 'Alumno editado con éxito' });
    });
}

function editProfessor(professorId, body, res) {
    const { nombre, contraseña, email } = JSON.parse(body);
    const query = 'UPDATE Usuarios SET nombre = ?, contraseña = ?, email = ? WHERE id = ? AND rol = "profesor"';
    connection.query(query, [nombre, contraseña, email, professorId], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al editar al profesor' });
            return;
        }
        sendResponse(res, 200, { message: 'Profesor editado con éxito' });
    });
}

function getTotalUsers(res) {
    const query = `
        SELECT 
            (SELECT COUNT(*) FROM Usuarios WHERE rol = 'profesor') AS totalProfesores,
            (SELECT COUNT(*) FROM Usuarios WHERE rol = 'estudiante') AS totalEstudiantes
    `;
    connection.query(query, (err, results) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al obtener el total de usuarios' });
            return;
        }
        sendResponse(res, 200, results[0]);
    });
}

/** FUNCIONES PARA PROFESOR **/

function assignTask(body, res) {
    try {
        const data = JSON.parse(body);
        const { titulo, descripcion, fecha_asignacion, fecha_entrega, ponderacion, recursos, nivel_dificultad } = data;

        // Validaciones
        if (!titulo || !descripcion || !fecha_entrega || ponderacion === undefined) {
            sendResponse(res, 400, { error: 'Todos los campos obligatorios deben estar completos' });
            return;
        }

        // Validar ponderación
        const pondValue = parseFloat(ponderacion);
        if (isNaN(pondValue) || pondValue < 0 || pondValue > 100) {
            sendResponse(res, 400, { error: 'La ponderación debe ser un número entre 0 y 100' });
            return;
        }

        // Validar fechas
        const fechaAsig = fecha_asignacion || new Date().toISOString().split('T')[0];
        if (new Date(fecha_entrega) < new Date(fechaAsig)) {
            sendResponse(res, 400, { error: 'La fecha de entrega no puede ser anterior a la fecha de asignación' });
            return;
        }

        // Validar nivel de dificultad
        const nivelesPermitidos = ['fácil', 'facil', 'media', 'difícil', 'dificil'];
        if (!nivelesPermitidos.includes(nivel_dificultad.toLowerCase())) {
            sendResponse(res, 400, { error: 'Nivel de dificultad no válido' });
            return;
        }

        const query = `
            INSERT INTO Tareas (
                titulo, 
                descripcion, 
                fecha_asignacion, 
                fecha_entrega, 
                ponderacion, 
                estado, 
                recursos, 
                nivel_dificultad
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;

        connection.query(
            query, 
            [
                titulo,
                descripcion,
                fechaAsig,
                fecha_entrega,
                pondValue,
                'pendiente', 
                recursos || null,
                nivel_dificultad
            ], 
            (err, result) => {
                if (err) {
                    console.error('Error en la base de datos:', err);
                    sendResponse(res, 500, { 
                        error: 'Error al asignar la tarea',
                        details: process.env.NODE_ENV === 'development' ? err.message : undefined
                    });
                    return;
                }
                sendResponse(res, 201, { 
                    message: 'Tarea asignada con éxito', 
                    taskId: result.insertId 
                });
            }
        );
    } catch (error) {
        console.error('Error al procesar la solicitud:', error);
        sendResponse(res, 500, { error: 'Error interno del servidor' });
    }
}

function deletetask(taskId, res) {
    const query = 'DELETE FROM Tareas WHERE id = ?';
    connection.query(query, [taskId], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al eliminar la Tarea' });
            return;
        }
        sendResponse(res, 200, { message: 'Tarea eliminada con éxito' });
    });
}

function editTask(taskId, body, res) {
    try {
        const data = JSON.parse(body);
        const { titulo, descripcion, fecha_entrega, ponderacion, recursos, nivel_dificultad } = data;

        // Normalizar nivel_dificultad (quitar tildes y convertir a minúsculas)
        const normalizeDificultad = (nivel) => {
            const normalizado = nivel.toLowerCase()
                .normalize("NFD")
                .replace(/[\u0300-\u036f]/g, "");
            
            // Mapeo de valores permitidos
            const valoresPermitidos = {
                'facil': 'facil',
                'media': 'media',
                'dificil': 'dificil'
            };

            return valoresPermitidos[normalizado] || 'media';
        };

        const nivelNormalizado = normalizeDificultad(nivel_dificultad);

        const updateQuery = `
            UPDATE Tareas 
            SET 
                titulo = ?,
                descripcion = ?,
                fecha_entrega = ?,
                ponderacion = ?,
                recursos = ?,
                nivel_dificultad = ?
            WHERE id = ?
        `;

        const values = [
            titulo,
            descripcion,
            fecha_entrega,
            ponderacion,
            recursos || null,
            nivelNormalizado,
            taskId
        ];

        console.log('Valores normalizados:', values);

        connection.query(updateQuery, values, (err, result) => {
            if (err) {
                console.error('Error en la actualización:', err);
                sendResponse(res, 500, { error: 'Error al editar la tarea' });
                return;
            }
            sendResponse(res, 200, { message: 'Tarea editada con éxito' });
        });
    } catch (error) {
        console.error('Error al procesar la solicitud:', error);
        sendResponse(res, 500, { error: 'Error interno del servidor' });
    }
}

function viewAssignedTasks(res) {
    const query = 'SELECT id, titulo, descripcion, fecha_entrega, puntos_maximos, ponderacion FROM Tareas';
    connection.query(query, (err, results) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al obtener las tareas asignadas' });
            return;
        }
        sendResponse(res, 200, results);
    });
}

function countTasks(res) {
    const query = 'SELECT COUNT(*) AS totalTareas FROM Tareas';
    connection.query(query, (err, results) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al contar las tareas' });
            return;
        }
        sendResponse(res, 200, { totalTareas: results[0].totalTareas });
    });
}

function listTasks(res) {
    const query = 'SELECT id, titulo, descripcion, fecha_entrega, ponderacion, recursos, nivel_dificultad FROM Tareas';
    connection.query(query, (err, results) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al listar las tareas' });
            return;
        }
        sendResponse(res, 200, { tareas: results });
    });
}

function countPendingGrades(res) {
    const query = `
        SELECT COUNT(*) AS calificacionesPendientes 
        FROM Calificaciones 
        WHERE calificacion IS NULL;
    `;
    connection.query(query, (err, results) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al contar calificaciones pendientes' });
            return;
        }
        sendResponse(res, 200, { calificacionesPendientes: results[0].calificacionesPendientes });
    });
}

function addGrade(body, res) {
    try {
        console.log('Body recibido para calificación:', body);
        const parsedData = JSON.parse(body);
        console.log('Datos parseados:', parsedData);

        const { taskId, studentId, grade } = parsedData;

        // Validar datos
        if (!taskId || !studentId || grade === undefined) {
            sendResponse(res, 400, { error: 'Faltan datos requeridos' });
            return;
        }

        const date = new Date().toISOString().split('T')[0];
        
        // Primero verificar si existe el registro
        const checkQuery = 'SELECT id FROM Calificaciones WHERE tarea_id = ? AND estudiante_id = ?';
        
        connection.query(checkQuery, [taskId, studentId], (checkErr, checkResults) => {
            if (checkErr) {
                console.error('Error al verificar registro:', checkErr);
                sendResponse(res, 500, { error: 'Error al verificar registro' });
                return;
            }

            if (checkResults.length > 0) {
                // Actualizar registro existente
                const updateQuery = `
                    UPDATE Calificaciones 
                    SET calificacion = ?,
                        fecha_calificacion = ?,
                        estado = 'entregado'
                    WHERE tarea_id = ? AND estudiante_id = ?
                `;

                connection.query(updateQuery, [grade, date, taskId, studentId], (updateErr) => {
                    if (updateErr) {
                        console.error('Error al actualizar calificación:', updateErr);
                        sendResponse(res, 500, { error: 'Error al actualizar calificación' });
                        return;
                    }

                    sendResponse(res, 200, {
                        success: true,
                        message: 'Calificación actualizada exitosamente',
                        data: { grade, estado: 'entregado' }
                    });
                });
            } else {
                // Insertar nuevo registro
                const insertQuery = `
                    INSERT INTO Calificaciones 
                    (tarea_id, estudiante_id, calificacion, fecha_calificacion, estado)
                    VALUES (?, ?, ?, ?, 'entregado')
                `;

                connection.query(insertQuery, [taskId, studentId, grade, date], (insertErr) => {
                    if (insertErr) {
                        console.error('Error al insertar calificación:', insertErr);
                        sendResponse(res, 500, { error: 'Error al crear calificación' });
                        return;
                    }

                    sendResponse(res, 201, {
                        success: true,
                        message: 'Calificación agregada exitosamente',
                        data: { grade, estado: 'entregado' }
                    });
                });
            }
        });
    } catch (error) {
        console.error('Error al procesar calificación:', error);
        sendResponse(res, 400, { error: 'Error en el formato de los datos' });
    }
}


// Obtener lista de estudiantes
function getStudents(res) {
    const query = 'SELECT id, nombre, email FROM Usuarios WHERE rol = "estudiante"';
    connection.query(query, (err, results) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al obtener la lista de estudiantes' });
            return;
        }
        sendResponse(res, 200, results);
    });
}

// Obtener entregas y calificaciones por tarea
function getTaskSubmissions(taskId, res) {
    const query = `
        SELECT 
            c.id,
            c.tarea_id,
            c.estudiante_id,
            c.calificacion,
            c.fecha_calificacion,
            c.estado,
            u.nombre as estudiante_nombre,
            u.email as estudiante_email
        FROM Calificaciones c
        RIGHT JOIN Usuarios u ON c.estudiante_id = u.id AND c.tarea_id = ?
        WHERE u.rol = 'estudiante'
    `;
    
    connection.query(query, [taskId], (err, results) => {
        if (err) {
            console.error('Error al obtener submissions:', err);
            sendResponse(res, 500, { error: 'Error al obtener las entregas' });
            return;
        }
        console.log('Submissions obtenidas:', results);
        sendResponse(res, 200, results);
    });
}

// Actualizar estado de tarea
function updateTaskStatus(taskId, body, res) {
    const { estado } = JSON.parse(body);
    const query = 'UPDATE Tareas SET estado = ? WHERE id = ?';
    
    connection.query(query, [estado, taskId], (err, result) => {
        if (err) {
            sendResponse(res, 500, { error: 'Error al actualizar el estado de la tarea' });
            return;
        }
        sendResponse(res, 200, { message: 'Estado de tarea actualizado con éxito' });
    });
}

function updateSubmissionStatus(body, res) {
    try {
        console.log('Body recibido:', body);
        const { taskId, studentId, estado } = JSON.parse(body);
        
        console.log('Datos a procesar:', { taskId, studentId, estado });

        // Verificar que tenemos todos los datos necesarios
        if (!taskId || !studentId || !estado) {
            console.error('Datos incompletos:', { taskId, studentId, estado });
            sendResponse(res, 400, { error: 'Datos incompletos' });
            return;
        }

        const checkQuery = 'SELECT id FROM Calificaciones WHERE tarea_id = ? AND estudiante_id = ?';
        
        connection.query(checkQuery, [taskId, studentId], (checkErr, checkResults) => {
            if (checkErr) {
                console.error('Error en checkQuery:', checkErr);
                sendResponse(res, 500, { error: 'Error al verificar el registro' });
                return;
            }

            if (checkResults.length > 0) {
                // Actualizar registro existente
                const updateQuery = `
                    UPDATE Calificaciones 
                    SET estado = ?,
                        calificacion = CASE 
                            WHEN ? = 'pendiente' THEN NULL 
                            ELSE calificacion 
                        END,
                        fecha_calificacion = CASE 
                            WHEN ? = 'pendiente' THEN NULL 
                            ELSE fecha_calificacion 
                        END
                    WHERE tarea_id = ? AND estudiante_id = ?
                `;
                
                connection.query(updateQuery, [estado, estado, estado, taskId, studentId], (updateErr) => {
                    if (updateErr) {
                        console.error('Error en updateQuery:', updateErr);
                        sendResponse(res, 500, { error: 'Error al actualizar el estado' });
                        return;
                    }
                    
                    console.log('Estado actualizado exitosamente');
                    sendResponse(res, 200, { 
                        success: true,
                        message: 'Estado actualizado con éxito' 
                    });
                });
            } else {
                // Crear nuevo registro
                const insertQuery = `
                    INSERT INTO Calificaciones 
                    (tarea_id, estudiante_id, estado, calificacion, fecha_calificacion) 
                    VALUES (?, ?, ?, NULL, NULL)
                `;
                
                connection.query(insertQuery, [taskId, studentId, estado], (insertErr) => {
                    if (insertErr) {
                        console.error('Error en insertQuery:', insertErr);
                        sendResponse(res, 500, { error: 'Error al crear el registro' });
                        return;
                    }
                    
                    console.log('Nuevo registro creado exitosamente');
                    sendResponse(res, 201, { 
                        success: true,
                        message: 'Estado creado con éxito' 
                    });
                });
            }
        });
    } catch (error) {
        console.error('Error al procesar la solicitud:', error);
        sendResponse(res, 500, { error: 'Error interno del servidor' });
    }
}

/** FUNCIONES PARA USUARIO Y PROFESOR **/

function getStudentGradesWithAverage(studentId, res) {
    const queryCalificaciones = `
        SELECT 
            t.titulo AS tarea,
            t.ponderacion,
            c.calificacion,
            c.fecha_calificacion
        FROM 
            Calificaciones c
        JOIN 
            Tareas t ON c.tarea_id = t.id
        WHERE 
            c.estudiante_id = ?;
    `;

    const queryPromedio = `
        SELECT 
            SUM(c.calificacion * t.ponderacion / 100) AS promedio_final
        FROM 
            Calificaciones c
        JOIN 
            Tareas t ON c.tarea_id = t.id
        WHERE 
            c.estudiante_id = ?;
    `;

    connection.query(queryCalificaciones, [studentId], (error, resultadosCalificaciones) => {
        if (error) {
            sendResponse(res, 500, { error: 'Error al obtener calificaciones' });
            return;
        }

        connection.query(queryPromedio, [studentId], (error, resultadoPromedio) => {
            if (error) {
                sendResponse(res, 500, { error: 'Error al calcular el promedio' });
                return;
            }

            sendResponse(res, 200, {
                calificaciones: resultadosCalificaciones,
                promedio_final: resultadoPromedio[0].promedio_final
            });
        });
    });
}



const server = http.createServer((req, res) => {
    // Configurar CORS
    setCORSHeaders(res);

    console.log('Request Headers:', req.headers);

    // Manejar preflight requests
    if (req.method === 'OPTIONS') {
        sendResponse(res, 204, null);
        return;
    }

    const { method, url } = req;
    let body = '';

    req.on('data', chunk => { 
        body += chunk.toString(); 
    });

    req.on('end', () => {
        try {
            if (url === '/api/login' && method === 'POST') {
                loginUser(body, res);
            } else if (url === '/api/register' && method === 'POST') {
                registerUser(body, res);
            }
            else if (url === '/api/login' && method === 'POST') {
                loginUser(body, res);
            } else if (url === '/api/add-user' && method === 'POST') {
                addUser(body, res);
            } else if (url === '/api/assign-task' && method === 'POST') {
                assignTask(body, res);
            } else if (url === '/api/view-tasks' && method === 'GET') {
                viewAssignedTasks(res);
            } else if (url.startsWith('/api/students/delete/') && method === 'DELETE') {
                const studentId = url.split('/')[4];
                deleteStudent(studentId, res);
            } else if (url.startsWith('/api/professors/delete/') && method === 'DELETE') {
                const professorId = url.split('/')[4];
                deleteProfessor(professorId, res);
            } else if (url.startsWith('/api/students/edit/') && method === 'PUT') {
                const studentId = url.split('/')[4];
                editStudent(studentId, body, res);
            } else if (url.startsWith('/api/professors/edit/') && method === 'PUT') {
                const professorId = url.split('/')[4];
                editProfessor(professorId, body, res);
            } else if (url === '/api/total-users' && method === 'GET') {
                getTotalUsers(res);
            } else if (url === '/api/tasks/count' && method === 'GET') {
                countTasks(res);
            } else if (url === '/api/grades/pending/count' && method === 'GET') {
                countPendingGrades(res);
            } else if (url.startsWith('/api/grades/student/') && method === 'GET') {
                const studentId = url.split('/')[4];
                getStudentGradesWithAverage(studentId, res);
            } else if (url === '/api/listusers' && method === 'GET') {
                listusers(req,res);
                return;

            }else if (url === '/api/registerallkindausers' && method === 'POST'){
                registerallkindausers(body,res);
            }else if(url.startsWith('/api/edit-task/') && method === 'PUT'){
                const taskId = url.split('/')[3];
                editTask(taskId,body,res);
            }else if(url.startsWith('/api/delete-task/') && method === 'DELETE'){
                const taskId = url.split('/')[3];
                deletetask(taskId,res);
            }else if(url === '/api/listtask' && method === 'GET'){
                listTasks(res);
            }
            else if (url === '/api/professor/add-grade' && method === 'POST') {
                    addGrade(body, res);
            } else if (url === '/api/students' && method === 'GET') {
                getStudents(res);
            } else if (url.startsWith('/api/task-submissions/') && method === 'GET') {
                const taskId = url.split('/')[3];
                getTaskSubmissions(taskId, res);
            } else if (url.startsWith('/api/task-status/') && method === 'PUT') {
                const taskId = url.split('/')[3];
                updateTaskStatus(taskId, body, res);
            } else if (url === '/api/update-submission-status' && method === 'POST') {
    updateSubmissionStatus(body, res);
}
            else {
                sendResponse(res, 404, { error: 'Ruta no encontrada' });
            }
        } catch (error) {
            console.error('Error en el servidor:', error);
            sendResponse(res, 500, { error: 'Error interno del servidor' });
        }
    });
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Servidor en ejecución en http://localhost:${PORT}`);
});