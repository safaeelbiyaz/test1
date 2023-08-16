const express = require("express");
const jwt = require('jsonwebtoken');
const app = express();
const router = express.Router();
const bodyParser = require("body-parser");
const bcrypt = require('bcrypt');
//const fs = require('fs');
const { Pool } = require('pg');
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'testdb',
  password: 'malika',
  port: 5432,
  dialect: "postgres",
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});
// pool.connect();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set("view engine", "ejs");
app.use(express.static(__dirname + "/public"));
app.get("/register", (req, res) => res.render("register"));
app.get("/login", (req, res) => res.render("login"));
app.get("/Homepage", (req, res) => res.render("index"));
app.get("/Homepage1", (req, res) => res.render("index1"));
app.get("/dash", (req, res) => res.render("dash1"))
app.get("/", (req, res) => res.render("homepage"));
app.get("/dashboard", (req, res) => res.render("dashboardc"));
app.get("/charts", (req, res) => res.render("charts"));
app.get("/protected-resource", (req, res) => res.render("Homepage"));

app.use("/", router);
app.use(express.json());

app.post('/registerUser', async (req, res) => {
  const { firstname, lastname, email, password } = req.body;
  console.log(firstname, '.............', lastname)
  let hashedPassword = await bcrypt.hash(password, 8);

  const selectQuery = 'SELECT email FROM users WHERE email = $1';
  const selectValues = [email];

  pool.query(selectQuery, selectValues, (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send({ success: false, message: 'Internal Server Error' });
    }

    if (result.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'That email is already in use' });
    }

    const insertQuery = 'INSERT INTO users (firstname,lastname, email, password,role,active) VALUES ($1, $2, $3,$4,$5,$6) RETURNING *';
    const role = "user"
    const active = true
    const insertValues = [firstname, lastname, email, hashedPassword, role, active];

    pool.query(insertQuery, insertValues, (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send({ success: false, message: 'Internal Server Error' });
      }

      return res.json({ success: true, data: result.rows[0] });
    });
  });
});

app.post('/loginUser', async (req, res) => {
const crypto = require('crypto');
const generateSecretKey = () => {
  const length = 64;
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
};
const secretKey = generateSecretKey();
console.log('Secret key:', secretKey);
  const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'testdb',
    password: 'malika',
    port: 5432,
    dialect: "postgres",
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  });

  const { email, password } = req.body;
  console.log('datatata:', req.body)
  const sqlQuery = 'SELECT * FROM users where email = $1';
  const value = [email];

  pool.query(sqlQuery, value, async (error, result) => {
    if (error) {
      console.error('Error executing query:', error.stack);
    } else {
      if (result.rows.length === 0) {
        console.log('User not found');
        res.send('User not found');
        return;
      }
      const { hashed_password } = result.rows[0];
      const safae = result.rows[0].password;
      console.log('sssssssss:', safae);
      const isMatch = await bcrypt.compare(password, safae);
      const active = result.rows[0].active;
      const userId = parseInt(result.rows[0].id_user)
      console.log('USERTD', userId)
      // add this function to generate a token
      function generateToken(userId) {
        // create a payload with the user id and a secret key
        const payload = {
          sub: userId,
          iat: Date.now(),
          "role":result.rows[0].role,
          //"idUser":result.rows[0].id_user
        };
        // create and sign the token with the payload and secret key
        const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });
        console.log('TOKEN:', token);
        return token;
      }
      if (active === 'true') {
        if (isMatch) {
          //console.log('MATCH');
          // create a token for the user
          const token = generateToken(userId);
          //const sa=JSON.stringify(token)
          const pool = new Pool({
            user: 'postgres',
            host: 'localhost',
            database: 'testdb',
            password: 'malika',
            port: 5432,
            dialect: "postgres",
            pool: {
              max: 5,
              min: 0,
              acquire: 30000,
              idle: 10000
            }
          });
          // insert the token into the token table
          const insertQuery = 'INSERT INTO tokens (token, id_user) VALUES ($1, $2)';
          const insertValues = [token, userId];
          pool.query(insertQuery, insertValues, (err, result) => {
            if (err) {
              console.error('Error inserting token:', err.stack);
            } else {
              console.log('Token inserted successfully');
            }
          });

          // return the token in the response
          res.json({ success: true, message: 'login success', userId });
          
        } else {
          console.log('Passwords do not match.');
          res.json({ success: false, message: 'login failed' });
        }
      } else {
        console.log('user not active');
      }
    }
    pool.end();
  });
  // Middleware function to verify the token
function verifyToken(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send('Unauthorized. Token not provided.');
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).send('Unauthorized. Invalid token.');
    }

    req.user = decoded;
    next();
  });
}

app.get('/getUserRole', verifyToken, (req, res) => {
  // Access the user's role from the decoded token
  const userRole = req.user.role;
  
  // Return the user's role in the response
  res.json({ role: userRole });
});

});



app.post('/logout', (req, res) => {
  const {data} = req.body;
console.log('USERID:::',data)
  // Delete the token from the token table
  const deleteQuery = 'DELETE FROM tokens WHERE id_user = $1';
  const deleteValues = [data];
  pool.query(deleteQuery, deleteValues, (err, result) => {
    if (err) {
      console.error('Error deleting token:', err.stack);
      res.json({ success: false, message: 'logout failed' });
    } else {
      console.log('Token deleted successfully');
      res.json({ success: true, message: 'logout success' });
    }
  });
});


// app.post('/savePolygon', (req, res) => {
//   const { coordinates, properties } = req.body;

//   const wkt = `POLYGON((${coordinates[0].map(c => c.join(' ')).join(',')}))`;
//   console.log('the new cooordinates :::::::::::::', wkt);
//   const geom = `ST_GeomFromText('${wkt}', 4326)`;
//   console.log(geom);

//   const query = `
//     INSERT INTO polygones(geom, name, mappe, numero, type ,nature ,indice ,complement , surface)
//     VALUES (${geom}, $1, $2, $3, $4 ,$5 ,$6 ,$7,$8 )
//   `;
//   const { id_couche } = req.body;
//   const values = [properties.name, properties.mappe, properties.numero, properties.type, properties.nature, properties.indice, properties.complement, properties.surface,id_couche];

//   pool.query(query, values, (err, dbRes) => {
//     if (err) {
//       console.error('Error inserting data', err.stack);
//       res.status(500).send('Error inserting data');
//     } else {
//       console.log('Data inserted');
//       res.status(200).send('Data inserted');
//     }
//   });
// });
app.post('/savePolygontwo', (req, res) => {
  const { coordinates, properties, id_couche } = req.body;

  const wkt = `POLYGON((${coordinates[0].map(c => c.join(' ')).join(',')}))`;
  console.log('the new coordinates :::::::::::::', wkt);
  const geom = `ST_GeomFromText('${wkt}', 4326)`;
  console.log(geom);

  const query = `
    INSERT INTO polygones(geom, name, mappe, numero, type, nature, indice,  surface, id_couche)
    VALUES (${geom}, $1, $2, $3, $4, $5, $6, $7, $8)
  `;

  const values = [
    properties.name,
    properties.mappe,
    properties.numero,
    properties.type,
    properties.nature,
    properties.indice,
    properties.surface,
    id_couche
  ];

  pool.query(query, values, (err, dbRes) => {
    if (err) {
      console.error('Error inserting data', err.stack);
      res.status(500).send('Error inserting data');
    } else {
      console.log('Data inserted');
      res.status(200).send('Data inserted');
    }
  });
});
app.post('/saveCouche', (req, res) => {
  const { name_couche, id_user } = req.body;
 // const { id_user } = req.body;

  const query = `
    INSERT INTO couches(name_couche ,id_user)
    VALUES ( $1 ,$2)
  `;
  
  const values = [name_couche,id_user];
  console.log(values)

  pool.query(query, values, (err, dbRes) => {
    if (err) {
      console.error('Error inserting data', err.stack);
      res.status(500).send('Error inserting data');
    } else {
      console.log('Data inserted');
      res.status(200).send('Data inserted');
    }
  });
});
app.get('/GeoJsondata', function (req, res) {
  const { id_couche } = req.query;
  const value = [id_couche];
  const query = `SELECT json_build_object(
    'type', 'Feature',
    'geometry', ST_AsGeoJSON(geom)::json,
    'properties', json_build_object(
      'id_polygon', id_polygon,
      'name', name,
      'mappe', mappe,
      'numero', numero,
      'type', type,
      'nature', nature,
      'indice', indice,
      'surface', surface,
      'id_couche', id_couche
    )
  )::text AS geojson FROM public.polygones WHERE id_couche = $1`;

  pool.query(query, value, (err, result) => {
    if (err) {
      console.error(err);
      res.json({ success: false, message: err.message });
    } else {
      let data = result.rows.map(row => JSON.parse(row.geojson));
      res.json({ success: true, data: data });
    }
  });
});



app.post('/couchesdata', function(req, res) {
  const { data } = req.body; // Access the data from the request body

  const value = [data];
  //console.log('IDUSER===', value);

  const sqlquery = "SELECT name_couche,id_couche FROM couches WHERE id_user =$1";
  pool.query(sqlquery, value, async (err, result) => {
    if (err) {
      console.error(err);
      res.json({ success: false, message: err.message });
    } else {
      res.json({ success: true, data: result.rows });
      //console.log(result.rows);

    }
  });
});
app.post('/updatecouchedata', function(req, res) {
  const {  id_couche,newname } = req.body; // Access the data from the request body

  const value = [id_couche,newname];
  console.log('iiiiidddddddd::::',value)
  //console.log('IDUSER===', value);

  const sqlqueryupdated = "UPDATE couches SET name_couche = $2 WHERE id_couche=$1";
  pool.query(sqlqueryupdated, value, async (err, result) => {
    if (err) {
      console.error(err);
      res.json({ success: false, message: err.message });
    } else {
      res.json({ success: true, data: result.rows });
      //console.log(result.rows);

    }
  });
});
app.post('/deletecouches', function(req, res) {
  const { id_couche, id_user } = req.body;

  const values = [id_couche, id_user];
  console.log(values);

  const sqlquery = `
    WITH deleted_polygones AS (
      DELETE FROM polygones
      WHERE id_couche = $1
      RETURNING id_couche
    )
    DELETE FROM couches
    WHERE id_couche = $1 AND id_user = $2;
  `;
  
  pool.query(sqlquery, values, async (err, result) => {
    if (err) {
      console.error(err);
      res.json({ success: false, message: err.message });
    } else {
      res.json({ success: true, data: result.rows });
    }
  });
});


async function fetchData() {
  const client = await pool.connect();
  try {
    // Execute your query to retrieve the data from the database
    const query = 'SELECT * FROM polygones';
    const result = await client.query(query);

    // Return the retrieved data
    return result.rows;
  } finally {
    // Release the database client
    client.release();
  }
}
app.get('/data', async (req, res) => {
  try {
    const data = await fetchData();
    res.json(data);
    console.log(data)
  } catch (error) {
    console.error('Error retrieving data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});




app.get('/GeoJsondataRabatHassane', function (req, res) {
  pool.query(
    "SELECT json_build_object(" +
    "'type', 'Feature'," +
    "'geometry', ST_AsGeoJSON(ST_Transform(geom, 4326))::json," +
    "'properties', json_build_object(" +
    "'id', id," +
    "'mappe', \"mappe\"," +
    "'nature', \"nature\"," +
    "'num', \"num\"," +
    "'indice', indice," +
    "'complement', complement," +
    "'type', \"type\"," +
    "'nb_bornes', \"nb_bornes\"," +
    "'surf_calc', \"surf_calc\"," +
    "'surf_adop', \"surf_adop\"," +
    "'consistanc', \"consistanc\"," +
    "'titre_min1', \"titre_min1\"," +
    "'titre_max1', \"titre_max1\"," +
    "'titre_min2', \"titre_min2\"," +
    "'titre_max2', \"titre_max2\"," +
    "'tit', tit," +
    "'control', control," +
    "'reperage', reperage," +
    "'carnet', carnet," +
    "'bon', \"bon\"," +
    "'datecb', \"datecb\"," +
    "'archive', \"archive\"," +
    "'titref', \"titref\"," +
    "'graphic_de', \"graphic_de\"" +
    ")" +
    ")::text FROM hassane",
    function (err, result) {
      if (err) {
        console.error(err);
        res.json({ success: false, message: err.message });
      } else {
        let data = result.rows.map(row => JSON.parse(row.json_build_object));
        console.log('data:', data)
        res.json({ success: true, data: data });
      }
    }
  );
});
app.get('/GeoJsondataRabatRiyad', function (req, res) {
  pool.query(
    "SELECT json_build_object(" +
    "'type', 'Feature'," +
    "'geometry', ST_AsGeoJSON(ST_Transform(geom, 4326))::json," +
    "'properties', json_build_object(" +
    "'id', id," +
    "'mappe', \"mappe\"," +
    "'nature', \"nature\"," +
    "'num', \"num\"," +
    "'indice', indice," +
    "'complement', complement," +
    "'type', \"type\"," +
    "'nb_bornes', \"nb_bornes\"," +
    "'surf_calc', \"surf_calc\"," +
    "'surf_adop', \"surf_adop\"," +
    "'consistanc', \"consistanc\"," +
    "'titre_min1', \"titre_min1\"," +
    "'titre_max1', \"titre_max1\"," +
    "'titre_min2', \"titre_min2\"," +
    "'titre_max2', \"titre_max2\"," +
    "'tit', tit," +
    "'control', control," +
    "'reperage', reperage," +
    "'carnet', carnet," +
    "'bon', \"bon\"," +
    "'datecb', \"datecb\"," +
    "'archive', \"archive\"," +
    "'valider', \"valider\"," +
    "'prop', \"prop\"," +
    "'titref', \"titref\"," +
    "'graphic_de', \"graphic_de\"," + // Add a comma after "graphic_de"
    "'cop', \"cop\"," +
    "'proprietai', \"proprietai\"," +
    "'xm', \"xm\"," +
    "'ym', \"ym\"" + // Remove the comma at the end of the line
    ")" +
    ")::text FROM riyad",
    function (err, result) {
      if (err) {
        console.error(err);
        res.json({ success: false, message: err.message });
      } else {
        let data = result.rows.map(row => JSON.parse(row.json_build_object));
        console.log('data:', data)
        res.json({ success: true, data: data });
      }
    }
  );
});
app.get('/GeoJsondataSalaEljadida', function (req, res) {
  pool.query(
    "SELECT json_build_object(" +
    "'type', 'Feature'," +
    "'geometry', ST_AsGeoJSON(ST_Transform(geom, 4326))::json," +
    "'properties', json_build_object(" +
    "'id', id," +
    "'mappe', \"mappe\"," +
    "'nature', \"nature\"," +
    "'num', \"num\"," +
    "'indice', indice," +
    "'complement', complement," +
    "'type', \"type\"," +
    "'nb_bornes', \"nb_bornes\"," +
    "'surf_calc', \"surf_calc\"," +
    "'surf_adop', \"surf_adop\"," +
    "'consistanc', \"consistanc\"," +
    "'titre_min1', \"titre_min1\"," +
    "'titre_max1', \"titre_max1\"," +
    "'titre_min2', \"titre_min2\"," +
    "'titre_max2', \"titre_max2\"," +
    "'reperage', reperage," +
    "'carnet', carnet," +
    "'bon', \"bon\"," +
    "'datecb', \"datecb\"," +
    "'archive', \"archive\"," +
    "'tit', \"tit\"," +
    "'statut', \"statut\"," +
    "'titref', \"titref\"," +
    "'graphic_de', \"graphic_de\"" +
    ")" +
    ")::text FROM salaeljadida",
    function (err, result) {
      if (err) {
        console.error(err);
        res.json({ success: false, message: err.message });
      } else {
        let data = result.rows.map(row => JSON.parse(row.json_build_object));
        console.log('data:', data)
        res.json({ success: true, data: data });
      }
    }
  );
});
app.get('/GeoJsondataSaleMadina', function (req, res) {
  pool.query(
    "SELECT json_build_object(" +
    "'type', 'Feature'," +
    "'geometry', ST_AsGeoJSON(ST_Transform(geom, 4326))::json," +
    "'properties', json_build_object(" +
    "'id', id," +
    "'mappe', \"mappe\"," +
    "'nature', \"nature\"," +
    "'indice', indice," +
    "'complement', complement," +
    "'type', \"type\"," +
    "'nb_bornes', \"nb_bornes\"," +
    "'surf_calc', \"surf_calc\"," +
    "'surf_adop', \"surf_adop\"," +
    "'consistanc', \"consistanc\"," +
    "'titre_min1', \"titre_min1\"," +
    "'titre_max1', \"titre_max1\"," +
    "'titre_min2', \"titre_min2\"," +
    "'titre_max2', \"titre_max2\"," +
    "'reperage', reperage," +
    "'carnet', carnet," +
    "'bon', \"bon\"," +
    "'datecb', \"datecb\"," +
    "'archive', \"archive\"," +
    "'titref', \"titref\"," +
    "'graphic_de', \"graphic_de\"" + // Add a comma after "graphic_de"
    ")" +
    ")::text FROM public.salemedina",
    function (err, result) {
      if (err) {
        console.error(err);
        res.json({ success: false, message: err.message });
      } else {
        let data = result.rows.map(row => JSON.parse(row.json_build_object));
        console.log('data:', data)
        res.json({ success: true, data: data });
      }
    }
  );
});

app.listen(process.env.PORT || 3000);