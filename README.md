# OptiClick Backend - Eye Care API ⚙️  

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)

> **Final Degree Project Backend** - REST API powering OptiClick's appointment scheduling and patient history features.  

## 🔧 Key Functionality  
- **Authentication** (JWT) for patients/opticians  
- **CRUD Operations** for:  
  - 👥 User profiles  
  - 🗓️ Appointments  
  - 👁️ Vision history records

## ↔️ Endpoints  
| Method | Route                | Description              |  
|--------|----------------------|--------------------------|  
| POST   | `/api/register` | Patient registration     |  
| GET    | `/api/citas`  | Fetch booked sessions    |  

## 🚀 Deployment  
```bash
git clone https://github.com/carlosdelval/Opticlick_Backend.git
npm install
npm run dev  # Development
npm start    # Production
